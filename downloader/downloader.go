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
	Log							*logger.Logger
}

func NewDownloader(urlFile string, numParts int, maxConcurrentConnections int, partsDir string, prefixParts string, log *logger.Logger) *Downloader {
	return &Downloader{
		URLFile: urlFile, 
		NumParts: numParts,
		MaxConcurrentConnections: maxConcurrentConnections,
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Log: log,
	}
}

func (d *Downloader) initUIAndDownloadParameters() (int, atomic.Value) {
	var speed atomic.Value
	speed.Store("")
	return 0, speed
}

func (d *Downloader) makeHTTPClient() (*http.Client, error) {
	return &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 60 * time.Second,
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

func (d *Downloader) DownloadPart(client *http.Client, i, rangeSize, size int, sem chan struct{}, maxProgressFileNameLen int, progressBars []*uiprogress.Bar, partFilesHashes []string, speed atomic.Value, downloadManifest *manifest.DownloadManifest, wg *sync.WaitGroup) {
	go func(i int) {
		if d.MaxConcurrentConnections != 0 {
			sem <- struct{}{} // acquire a token
			defer func() { <-sem }() // release the token
		}

		defer wg.Done()

		timestamp := time.Now().UnixNano() // UNIX timestamp with nanosecond precision

		progressFileName := fmt.Sprintf("output part %d", i+1)
		outputPartFileName := fmt.Sprintf("%s%s-%s-%d.part", d.PartsDir, d.PrefixParts, uuid.New(), i+1)

		d.Log.Debugw("Debugging part files paths",
			"outputPartFileName", outputPartFileName,
			"partsDir", d.PartsDir,
		) // Add debug output

		outputPartFile, err := os.Create(outputPartFileName)
		if err != nil {
			d.Log.Fatalw("Error: Failed to create part file", "error", err)
		}
		defer outputPartFile.Close()

		if len(progressFileName) > maxProgressFileNameLen {
			maxProgressFileNameLen = len(progressFileName)
		}

		// Create a progress bar
		bar := uiprogress.AddBar(rangeSize).PrependElapsed()
		
		// Set the progress bar details
		bar.PrependFunc(func(b *uiprogress.Bar) string {
			return fmt.Sprintf("%-*s | %s | %s", maxProgressFileNameLen, progressFileName, utils.FormatFileSize(int64(b.Current())), utils.FormatFileSize(int64(rangeSize)))
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

		d.Log.Debugw(
			"Downloading range Start to End", 
			"Start", startLength,
			"End",	 endLength,
		) // Add debug output

		resp, err := client.Do(req) // Use the custom client
		if err != nil {
			d.Log.Fatalw("Error: Failed to execute HTTP request", "error", err)
		}
		defer resp.Body.Close()

		buf := utils.BufferPool.Get().([]byte) // Get a buffer from the pool
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
			bytesRead, err := reader.Read(buf)
			if bytesRead > 0 {
				// write a chunk
				_, err := writer.Write(buf[:bytesRead])
				if err != nil {
					d.Log.Fatalw("Error: Failed to write a chunk: ", "error", err)
				}

				// calculate elapsed time and add to total
				elapsed := time.Since(startTime)
				totalElapsedMilliseconds += elapsed.Microseconds()

				// add bytes downloaded to total
				totalBytesDownloaded += int64(bytesRead)

				// update progress bar
				bar.Set(int(totalBytesDownloaded)) // update the progress bar to the current total bytes downloaded
			}

			// handle end or error
			if err == io.EOF {
				break
			}
			if err != nil {
				d.Log.Fatalw("Error: Fatal", "error", err)
			}
			startTime = time.Now() // reset start time after processing the chunk
			currentSpeed := utils.FormatSpeed(totalBytesDownloaded, totalElapsedMilliseconds)
			speed.Store(currentSpeed)
		}

		// Close and reopen the file to calculate the hash
		outputPartFile.Close()
		outputPartFile, err = os.Open(outputPartFileName)
		if err != nil {
			d.Log.Fatalw("Error: Failed to open part file", "error", err)
		}
		defer outputPartFile.Close()

		// Calculate the hash from the temporary part file
		h := sha256.New()
		if _, err := io.Copy(h, outputPartFile); err != nil {
			d.Log.Fatalw("Error: Failed to calculate the hash from temporary file: ", "error", err)
		}
		sha256Hash := h.Sum(nil)
		sha256HashString := hex.EncodeToString(sha256Hash[:])
		partFilesHashes[i] = sha256HashString

		// Close the file before renaming
		outputPartFile.Close()

		partFileName := fmt.Sprintf("%s%s-%s-%d.part", d.PartsDir, d.PrefixParts, sha256HashString, timestamp)
		if err := os.Rename(outputPartFileName, partFileName); err != nil {
			d.Log.Fatalw("Error: Failed to rename the part file", "error", err)
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

		d.Log.Infow(
			"Writing to manifest file",
		)

		// Add downloaded part info to the download manifest
		downloadManifest.DownloadedParts = append(downloadManifest.DownloadedParts, manifest.DownloadedPart{
			PartNumber: i + 1,
			FileHash:   sha256HashString,
			Timestamp:  timestamp,
			PartFile:   outputPartFile.Name(),
		})

		d.Log.Debugw(
			"Downloaded part",
			"part file",			i+1,
			"sha256 hash string", 	sha256HashString, 
			"timestamp", 			timestamp,
			"filename", 			outputPartFile.Name(),
		) // Print the part being downloaded. Debug output

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

	var wg sync.WaitGroup
	wg.Add(d.NumParts)

	rangeSize := size / d.NumParts

	d.Log.Debugw(
		"Calculated File size and Range size",
		"FileSize",  size,
		"RangeSize", rangeSize,
	) // Print file size and range size. . Debug output

	parsedURL, err := url.Parse(d.URLFile)
	if err != nil {
		d.Log.Fatalw("Error: Invalid URL", "error", err)
	}

	// Get the file name from the URL
	fileName := path.Base(parsedURL.Path)

	// Get
	hash := hashes[fileName]

	// Create and initialize the download manifest
	downloadManifest := d.InitDownloadManifest(fileName, hash, etag, hashType, size, rangeSize)

	d.Log.Debugw("Inititalizing download manifest", "downloadManifest", downloadManifest) // Add debug output

	// Initialize the UI and download parameters
	maxProgressFileNameLen, speed := d.initUIAndDownloadParameters()

	// Create a new UI progress bar and start it
	uiprogress.Start()
	// defer uiprogress.Stop()

	progressBars := make([]*uiprogress.Bar, d.NumParts)
	partFilesHashes := make([]string, d.NumParts)

	sem := make(chan struct{}, d.MaxConcurrentConnections) // maxConcurrentConnections is the limit you set

	if d.MaxConcurrentConnections == 0 {
		d.Log.Debugw("Max concurrent connections not set. Downloading all parts at once.")
	}

	for i := 0; i < d.NumParts; i++ {
		go d.DownloadPart(client, i, rangeSize, size, sem, maxProgressFileNameLen, progressBars, partFilesHashes, speed, &downloadManifest, &wg)
	}

	wg.Wait()

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

	m.SaveDownloadManifest(downloadManifest, fileName, hash)

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