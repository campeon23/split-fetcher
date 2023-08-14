package downloader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/campeon23/multi-source-downloader/encryption"
	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/manifest"
	"github.com/campeon23/multi-source-downloader/utils"

	"github.com/google/uuid"
	"github.com/gosuri/uiprogress"
)

type Downloader struct {
	URLFile 					string 
	NumParts 					int 
	MaxConcurrentConnections 	int
	PartsDir 					string
	PrefixParts 				string
	Proxy 						string
	Log							*logger.Logger
}

func NewDownloader(urlFile string, numParts int, maxConcurrentConnections int, partsDir string, prefixParts string, proxy string, log *logger.Logger) *Downloader {
	return &Downloader{
		URLFile: urlFile, 
		NumParts: numParts,
		MaxConcurrentConnections: maxConcurrentConnections,
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Proxy: proxy,
		Log: log,
	}
}

func (d *Downloader) InitUIAndDownloadParameters() (int, atomic.Value, string) {
	var speed atomic.Value
	speed.Store("")
	progressbarName := "output part "
	maxProgressbarLen := len(progressbarName + fmt.Sprint(d.NumParts))
	return maxProgressbarLen, speed, progressbarName
}

// A simple function to check if a string starts with "http://"
func startsWithHTTP(s string) bool {
	return len(s) >= 7 && s[0:7] == "http://"
}

func (d *Downloader) makeHTTPClient() (*http.Client, error) {
	// Create a custom HTTP client
	var proxyFunc func(*http.Request) (*url.URL, error)
	if d.Proxy != "" {
		// Ensure the proxy has the correct format
		if !startsWithHTTP(d.Proxy) {
			d.Proxy = "http://" + d.Proxy
		}
		proxyURL, err := url.Parse(d.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		proxyFunc = http.ProxyURL(proxyURL)
		d.Log.Debugw(
			"Using proxy url", 
			"proxyURL", proxyURL,
		)
	} else {
		proxyFunc = http.ProxyFromEnvironment
	}

	d.Log.Debugw(
			"Using proxy function", 
			"proxy", d.Proxy,
			"proxyFunc", proxyFunc,
		)

	return &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 60 * time.Second,
			Proxy:               proxyFunc,
		},
	}, nil
}

func (d *Downloader) InitDownloadManifest(fileName, hash, etag, hashType string, size, rangeSize int) manifest.DownloadManifest {
	return manifest.DownloadManifest{
		Version:  "1.0",
		UUID:     uuid.New().String(),
		Filename: fileName,
		FileHash: hash,
		URL:      d.URLFile,
		Etag:     etag,
		HashType: hashType,
		Size:     size,
		NumParts: d.NumParts,
		RangeSize: rangeSize,
	}
}

func (d *Downloader) DownloadPart(client *http.Client, i, rangeSize, size int, sem chan struct{}, maxProgressbarNameLen int, progressbarName string, progressBars []*uiprogress.Bar, partFilesHashes []string, speed atomic.Value, downloadManifest *manifest.DownloadManifest, wg *sync.WaitGroup, errCh chan error) {
	f := fileutils.NewFileutils(d.PartsDir, d.PrefixParts, d.Log)
	u := utils.NewUtils(d.PartsDir, d.Log)
	go func(i int) {
		if d.MaxConcurrentConnections != 0 {
			sem <- struct{}{} // acquire a token
			defer func() { <-sem }() // release the token
		}
		defer wg.Done()

		timestamp := u.GenerateTimestamp() // UNIX timestamp with nanosecond precision

		progressbarName := fmt.Sprintf(progressbarName + "%d", i+1)
		outputPartFileName := fmt.Sprintf("%s"+ string(os.PathSeparator) +"%s-%s-%d.part", d.PartsDir, d.PrefixParts, uuid.New(), i+1)

		outputPartFile, err := os.Create(outputPartFileName)
		if err != nil {
			d.Log.Fatalw("Error: Failed to create part file", "error", err)
		}
		defer outputPartFile.Close()

		// Create a progress bar
		bar := uiprogress.AddBar(rangeSize).PrependElapsed()
		
		// Set the progress bar details
		bar.PrependFunc(func(b *uiprogress.Bar) string {
			return fmt.Sprintf("%-*s | %s | %s", maxProgressbarNameLen, progressbarName, utils.FormatFileSize(int64(b.Current())), utils.FormatFileSize(int64(rangeSize)))
		})
		bar.AppendFunc(func(b *uiprogress.Bar) string {
			return fmt.Sprintf("%s %s", utils.FormatPercentage(int64(b.Current()), int64(rangeSize)), speed.Load().(string))
		})

		// Save this progress bar in the progressBars slice
		progressBars[i] = bar

		startLength := i * rangeSize
		endLength := startLength + rangeSize - 1
		if i == d.NumParts - 1 {
			endLength = size - 1
		}

		totalSize := endLength - startLength + 1

		// Create a new HTTP request with the range header
		req, err := http.NewRequest("GET", d.URLFile, nil)
		if err != nil {
			d.Log.Fatalw("Error: Failed to create a new HTTP reaquest: ", "error", err)
		}

		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", startLength, endLength))

		resp, err := client.Do(req) // Use the custom client
		if err != nil {
			d.Log.Fatalw("Error: Failed to execute HTTP request", "error", err)
		}
		defer resp.Body.Close()

		buf := utils.BufferPool.Get().(*[]byte) // Get a buffer from the pool
		defer func() { 
			utils.BufferPool.Put(buf) 
		}() // Return the buffer to the pool when done

		reader := io.LimitReader(resp.Body, int64(totalSize))

		// Create a custom writer to track the progress
		writer := &utils.ProgressWriter{
			Bar: bar,
			W:   outputPartFile,
		}

		totalBytesDownloaded := int64(0)
		totalElapsedMilliseconds := int64(0)

		startTime := time.Now() // record start time of reading chunk
		for {
			// read a chunk
			bytesRead, err := reader.Read(*buf)
			if bytesRead > 0 {
				// write a chunk
				_, err := writer.Write((*buf)[:bytesRead])
				if err != nil {
					d.Log.Fatalw("Error: Failed to write a chunk: ", "error", err)
				}

				// calculate elapsed time and add to total
				elapsed := time.Since(startTime)
				totalElapsedMilliseconds += elapsed.Microseconds()

				// add bytes downloaded to total
				totalBytesDownloaded += int64(bytesRead)

				// Update the progress bar to the current total bytes downloaded
				if err := bar.Set(int(totalBytesDownloaded)); err != nil {
					d.Log.Infow("Warning: failed updating the progress bar: %v", err)
				}
			}

			// handle end or error
			if err == io.EOF {
				break
			}
			if err != nil {
				errCh <- fmt.Errorf("failed, io.EOF ecounted: %v", err)
				return
			}
			startTime = time.Now() // reset start time after processing the chunk
			currentSpeed := utils.FormatSpeed(totalBytesDownloaded, totalElapsedMilliseconds)
			speed.Store(currentSpeed)
		}

		// Close and reopen the file to calculate the hash
		outputPartFile.Close()
		outputPartFile, err = os.Open(outputPartFileName)
		if err != nil {
			errCh <- fmt.Errorf("failed to open part file %v", err)
			return
		}
		defer outputPartFile.Close()

		// Calculate the hash from the temporary part file
		h := sha256.New()
		if _, err := io.Copy(h, outputPartFile); err != nil {
			errCh <- fmt.Errorf("failed to calculate the hash from temporary file:  %v", err)
			return
		}
		sha256Hash := h.Sum(nil)
		sha256HashString := hex.EncodeToString(sha256Hash[:])
		partFilesHashes[i] = sha256HashString

		// Close the file before renaming
		outputPartFile.Close()

		partFileName := fmt.Sprintf("%s" + string(os.PathSeparator) + "%s-%s-%d.part", d.PartsDir, d.PrefixParts, sha256HashString, timestamp)

		if f.PathExists(outputPartFileName) && !f.PathExists(partFileName) {
			if err := os.Rename(outputPartFileName, partFileName); err != nil {
				errCh <- fmt.Errorf("failed to rename the part file:  %v", err)
				return
			}
		}

		// Reopen the file under the new name
		outputPartFile, err = os.OpenFile(partFileName, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			d.Log.Fatalw("Error: Failed to open the part file", "error", err)
		}
		defer outputPartFile.Close()

		if totalBytesDownloaded != int64(totalSize) {
			d.Log.Fatalw("Error: expected to read more bytes", "error", err)
		}

		// Add downloaded part info to the download manifest
		downloadManifest.DownloadedParts = append(downloadManifest.DownloadedParts, manifest.DownloadedPart{
			PartNumber: i + 1,
			FileHash:   sha256HashString,
			Timestamp:  timestamp,
			PartFile:   outputPartFile.Name(),
		})
	}(i)
}

func (d *Downloader) DownloadPartFiles(hashes map[string]string) (manifest.DownloadManifest, []string, int, string, string, int, string, error) {
	var hashType string

	client, err := d.makeHTTPClient()
	if err != nil {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", fmt.Errorf("failed to create HTTP client: %w", err)
	}

	d.Log.Infow("Performing HTTP request") // Add debug output

	size, etag, hashType, err := d.GetFileInfo(client)
	if err != nil {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", fmt.Errorf("failed to get file info: %w", err)
	}
	
	d.Log.Infow("Starting download")

	// Initialize wait group and error channel
	var wg sync.WaitGroup
	errCh := make(chan error, 1) // Buffered channel to prevent blocking

	wg.Add(d.NumParts)

	rangeSize := size / d.NumParts

	d.Log.Debugw(
		"Calculated File size and Range size",
		"FileSize",  size,
		"RangeSize", rangeSize,
	) // Print file size and range size. . Debug output

	parsedURL, err := url.Parse(d.URLFile)
	if err != nil {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", fmt.Errorf("error: Invalid URL: %w", err)
	}

	// Get the file name from the URL
	fileName := path.Base(parsedURL.Path)

	// Get
	hash := hashes[fileName]

	// Create and initialize the download manifest
	downloadManifest := d.InitDownloadManifest(fileName, hash, etag, hashType, size, rangeSize)

	d.Log.Debugw("Inititalizing download manifest", "downloadManifest", downloadManifest) // Add debug output

	// Initialize the UI and download parameters
	maxProgressbarNameLen, speed, progressbarName := d.InitUIAndDownloadParameters()

	// Create a new UI progress bar and start it
	uiprogress.Start()

	progressBars := make([]*uiprogress.Bar, d.NumParts)
	partFilesHashes := make([]string, d.NumParts)

	sem := make(chan struct{}, d.MaxConcurrentConnections) // maxConcurrentConnections is the limit you set

	if d.MaxConcurrentConnections == 0 {
		d.Log.Debugw("Max concurrent connections not set. Downloading all parts at once.")
	}

	var firstError error

	for i := 0; i < d.NumParts; i++ {
		go d.DownloadPart(client, i, rangeSize, size, sem, maxProgressbarNameLen, progressbarName, progressBars, partFilesHashes, speed, &downloadManifest, &wg, errCh)
	}

	go func() {
		for err := range errCh {
			if err != nil && firstError == nil { // capture only the first error
				firstError = fmt.Errorf("error captured in errChannel: %w", err)
			}
		}
		close(errCh)
	}()

	wg.Wait()

	// No need to read from errCh directly, just check the value of firstError
	if firstError != nil {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", fmt.Errorf("received error from goroutine: %w", firstError)
	} else {
		fmt.Println("No errors received from goroutine")
	}

	// Stop the progress bar after all downloads are complete
	uiprogress.Stop()

	return downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName, err
}

func (d *Downloader) GetFileInfo(client *http.Client) (size int, etag string, hashType string, err error) {
	req, err := http.NewRequest("HEAD", d.URLFile, nil)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to execute HTTP request: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return 0, "", "", fmt.Errorf("server returned non-200 status code: %d", res.StatusCode)
	}

	etag = strings.Trim(res.Header.Get("Etag"), "\"") // Remove double quotes

	if strings.HasPrefix(etag, "W/") {
		hashType = "weak"
		etag = etag[2:]
	} else if etag != "" {
		hashType = "strong"
	} else {
		hashType = "unknown"
	}

	d.Log.Debugw(
		"Received Etag and HashType", 
		"etag",		etag,
		"HashType", hashType,
	) // Print Etag and HashType. Debug output

	size, err = strconv.Atoi(res.Header.Get("Content-Length"))
	if err != nil {
		d.Log.Fatalw("Error: Invalid Content-Length received from server")
	}

	return size, etag, hashType, err
}

func (d *Downloader) Download(shaSumsURL string, partsDir string, prefixParts string, urlFile string, downloadOnly bool, outputFile string) (manifest.DownloadManifest, map[string]string, string, []byte, int, int, string, string, error){
	e := encryption.NewEncryption(d.PartsDir, d.PrefixParts, d.Log)
	f := fileutils.NewFileutils(d.PartsDir, d.PrefixParts, d.Log)
	h := hasher.NewHasher(d.Log)
	m := manifest.NewManifest(d.PartsDir, d.PrefixParts, d.Log)

	if urlFile == "" {
		if downloadOnly {
			d.Log.Fatalw("Error: --download-only requires --url flag")
		} else {
			d.Log.Fatalw("Error: --url flag required")
		}
	}

	hashes, _ := f.DownloadAndParseHashFile(h, shaSumsURL)

	downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName, err := d.DownloadPartFiles(hashes)
	if err != nil {
		d.Log.Fatalw("Error: ", err)
	}

	hash, err := f.CombinedMD5HashForPrefixedFiles(partsDir, prefixParts)
	if err != nil {
		d.Log.Fatalw("Error: Fail to obtain combined parts file hash.", err)
	}

	if !downloadOnly {
		// Validate the path of output file
		message, err := f.ValidatePath(outputFile)
		if err != nil {
			d.Log.Fatalw("Found an error validating path string.", err.Error())
		} else {
			d.Log.Debugw(message)
		}

		// Extract the path and filename from the output file
		filePath, _, err := f.ExtractPathAndFilename(outputFile)
		if err != nil {
			d.Log.Fatalf("Could not parse the string:%v", err.Error())
		}

		// Validate the path of the output file
		if filePath != "" {
			err = f.ValidateCreatePath(filePath)
			if err != nil {
				d.Log.Fatalw("Found an error validating path string: %s", err.Error())
			}
		}
	}

	err = m.SaveDownloadManifest(downloadManifest, fileName, hash)
	if err != nil {
		return manifest.DownloadManifest{}, make(map[string]string), "", nil, 0, 0, "", "", fmt.Errorf("failed updating the progress bar: %v", err)
	}

	key, err := e.CreateEncryptionKey(partFilesHashes)
	if err != nil {
		d.Log.Fatalw("Error: Failed to obtain the encryption key.", err)
	}

	manifestPath, err := m.GetDownloadManifestPath(fileName, hash)
	if err != nil {
		d.Log.Fatalw("Error: failed to obtain the path of the downloaded manifest.", err)
	}

	if f.PathExists(manifestPath + ".enc") {
		d.Log.Debugw("Encrypted manifest file exists. Deleting:", "file", manifestPath + ".enc")
		err := os.Remove(manifestPath + ".enc")
		if err != nil {
			d.Log.Fatalw("Removing manifest file: ", "error", err.Error())
		}
	}

	err = e.EncryptFile(manifestPath, key)
	if err != nil {
		d.Log.Fatalw("Encrypting manifest file: ", "error", err.Error())
	}

	if downloadOnly {
		d.Log.Infow("Part files saved to directory", "directory", partsDir)
	}

	return downloadManifest, hashes, manifestPath, key, size, rangeSize, etag, hashType, err
}