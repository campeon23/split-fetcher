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

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}
type Downloader struct {
	URLFile 					string 
	NumParts 					int 
	MaxConcurrentConnections 	int
	PartsDir 					string
	PrefixParts 				string
	Proxy 						string
	Log 						logger.LoggerInterface
	ErrCh 						chan error
}

func NewDownloader(urlFile string, numParts int, maxConcurrentConnections int, partsDir string, prefixParts string, proxy string, log logger.LoggerInterface, errCh chan error) *Downloader {
	return &Downloader{
		URLFile: urlFile, 
		NumParts: numParts,
		MaxConcurrentConnections: maxConcurrentConnections,
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Proxy: proxy,
		Log: log,
		ErrCh: errCh,
	}
}

func (d *Downloader) SetLogger(log logger.LoggerInterface) {
    d.Log = log
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
		PartsDir: d.PartsDir,
		PrefixParts: d.PrefixParts,
		Size:     size,
		NumParts: d.NumParts,
		RangeSize: rangeSize,
	}
}

func (d *Downloader) InitUI() (int, atomic.Value, string) {
	maxProgressbarNameLen, atomicSpeed, progressbarName := d.InitUIAndDownloadParameters()
	return maxProgressbarNameLen, atomicSpeed, progressbarName
}

func (d *Downloader) InitUIAndDownloadParameters() (int, atomic.Value, string) {
	var speed atomic.Value
	speed.Store("")
	progressbarName := "output part "
	maxProgressbarLen := len(progressbarName + fmt.Sprint(d.NumParts))
	return maxProgressbarLen, speed, progressbarName
}

// Setup and Initialization
func (d *Downloader) InitDownloadPart(u *utils.Utils, i int, progressbarName string) (int64, string, *os.File, string, error) {
    timestamp := u.GenerateTimestamp()
    progressbarName = fmt.Sprintf(progressbarName + "%d", i+1)
    outputPartFileName := fmt.Sprintf("%s" + string(os.PathSeparator) + "%s-%s-%d.part", d.PartsDir, d.PrefixParts, uuid.New(), i+1)
    outputPartFile, err := os.Create(outputPartFileName)
	if err != nil {
		return 0, "", nil, "", fmt.Errorf("failed to create part file: %w", err)
	}

    return timestamp, progressbarName, outputPartFile, outputPartFileName, nil
}

func (d *Downloader) InitDownloadAndParseHashFile(h *hasher.Hasher, shaSumsURL string) (map[string]string, error) {
	hashes := make(map[string]string)
	if len(shaSumsURL) != 0 {
		d.Log.Infow("Initializing HTTP request")
		d.Log.Debugw("Creating HTTP request for URL", "URL", shaSumsURL)

		var err error
		hashes, err = h.DownloadAndParseHashFile(shaSumsURL)
		if err != nil {
			return nil, fmt.Errorf("failed to download and parse shasum file: %w", err)
		}
	}

	return hashes, nil
}

func (d *Downloader) InitHTTPClient() (*http.Client, error) {
	client, err := d.makeHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	return client, nil
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

func (d *Downloader) CreateProgressbar(i int, rangeSize int, maxProgressbarNameLen int, progressbarName string, speed atomic.Value, progressBars []*uiprogress.Bar) (*uiprogress.Bar) {
	uiprogress.RefreshInterval = time.Millisecond * 1000
	// Create a progress bar
	bar := uiprogress.AddBar(rangeSize).PrependElapsed()
	
	// Set the progress bar details
	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return fmt.Sprintf("%-*s | %s | %s", maxProgressbarNameLen, progressbarName, utils.FormatFileSize(int64(b.Current())), utils.FormatFileSize(int64(rangeSize)))
	})

	// Save this progress bar in the progressBars slice
	progressBars[i] = bar

	return bar
}

// HTTP Request and Download
func (d *Downloader) DownloadFileChunk(client HTTPClient, start int, end int) (*http.Response, error) {
	// Create a new HTTP request with the range header
    req, err := http.NewRequest("GET", d.URLFile, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create a new HTTP reaquest: %w", err)
    }
    req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
    resp, err := client.Do(req) // Use the custom client
    if err != nil {
        return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
    }

    return resp, nil
}

func (d *Downloader) CreateBufferProgressbar(resp *http.Response, totalSize int, bar *uiprogress.Bar, outputPartFile *os.File) (*[]byte, io.Reader, *utils.ProgressWriter, int64, int64) {
	// Create a buffer, reader and writter
	buf := utils.BufferPool.Get().(*[]byte) // Get a buffer from the pool

	reader := io.LimitReader(resp.Body, int64(totalSize))

	// Create a custom writer to track the progress
	writer := &utils.ProgressWriter{
		Bar: bar,
		W:   outputPartFile,
	}

	totalBytesDownloaded := int64(0)
	totalElapsedMilliseconds := int64(0)

	return buf, reader, writer, totalBytesDownloaded, totalElapsedMilliseconds
}

func (d *Downloader) ReadStreamWriteFile(reader io.Reader, writer *utils.ProgressWriter, buf *[]byte, rangeSize int, totalBytesDownloaded int64, totalElapsedMilliseconds int64, speed atomic.Value, bar *uiprogress.Bar, outputPartFile *os.File, outputPartFileName string) (*os.File, int64, error) {
	// Append the speed function to the bar (just once)
	bar.AppendFunc(func(b *uiprogress.Bar) string {
		speedStr, ok := speed.Load().(string)
		if !ok {
		    speedStr = "N/A"
		}
		return fmt.Sprintf("%s %s", utils.FormatPercentage(int64(b.Current()), int64(rangeSize)), speedStr)
	})

	startTime := time.Now() // record start time of reading chunk
	for {
		// read a chunk
		bytesRead, err := reader.Read(*buf)
		if bytesRead > 0 {
			// write a chunk
			_, err := writer.Write((*buf)[:bytesRead])
			if err != nil {
				return nil, 0, fmt.Errorf("failed to write a chunk: %w", err)
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
			return nil, 0, fmt.Errorf("failed, io.EOF ecounted: %w", err)
		}
		startTime = time.Now() // reset start time after processing the chunk
		currentSpeed := utils.FormatSpeed(totalBytesDownloaded, totalElapsedMilliseconds)
		speed.Store(currentSpeed)
	}

	// Close and reopen the file to calculate the hash
	outputPartFile.Close()
	outputPartFile, err := os.Open(outputPartFileName)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open part file %w", err)
	}

	return outputPartFile, totalBytesDownloaded, nil
}

// File Hash Computation
func (d *Downloader) ComputeHash(i int, partFilesHashes []string, outputPartFile *os.File) (string, error) {
    h := sha256.New()
    if _, err := io.Copy(h, outputPartFile); err != nil {
		return "", fmt.Errorf("failed to calculate the hash from temporary file:  %w", err)
    }
    sha256Hash := h.Sum(nil)
	sha256HashString := hex.EncodeToString(sha256Hash[:])
	partFilesHashes[i] = sha256HashString

    return sha256HashString, nil
}

func (d *Downloader) RenameValidateOutputFile(f *fileutils.Fileutils, outputPartFile *os.File, outputPartFileName string, sha256HashString string, timestamp int64, totalBytesDownloaded int64, totalSize int) (string, error) {
	// Close the file before renaming
	outputPartFile.Close()

	partFileName := fmt.Sprintf("%s" + string(os.PathSeparator) + "%s-%s-%d.part", d.PartsDir, d.PrefixParts, sha256HashString, timestamp)

	if f.PathExists(outputPartFileName) && !f.PathExists(partFileName) {
		if err := os.Rename(outputPartFileName, partFileName); err != nil {
			return "", fmt.Errorf("failed to rename the part file:  %w", err)
		}
	}

	// Reopen the file under the new name
	outputPartFile, err := os.OpenFile(partFileName, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to open the part file: %w", err)
	}
	defer outputPartFile.Close()

	if totalBytesDownloaded != int64(totalSize) {
		return "", fmt.Errorf("expected to read more bytes: %w", err)
	}
	return outputPartFile.Name(), nil
}

// Update Download Manifest
func (d *Downloader) UpdateDownloadManifest(downloadManifest *manifest.DownloadManifest, i int, hash string, timestamp int64, outputPartFileName string) {
    downloadManifest.DownloadedParts = append(downloadManifest.DownloadedParts, manifest.DownloadedPart{
        PartNumber: i + 1,
        FileHash:   hash,
        Timestamp:  timestamp,
        PartFile:   outputPartFileName,
    })
}

func (d *Downloader) DownloadPart(client *http.Client, i int, rangeSize int, size int, sem chan struct{}, maxProgressbarNameLen int, progressbarName string, progressBars []*uiprogress.Bar, partFilesHashes []string, speed atomic.Value, downloadManifest *manifest.DownloadManifest, wg *sync.WaitGroup) {
    // This remains largely unchanged.
	f := fileutils.NewFileutils(d.PartsDir, d.PrefixParts, d.Log)
	u := utils.NewUtils(d.PartsDir, d.Log)
    go func(i int) {
        if d.MaxConcurrentConnections != 0 {
            sem <- struct{}{}
            defer func() { <-sem }()
        }
        defer wg.Done()

		// Initialie download part file process
        timestamp, progressbarName, outputPartFile, outputPartFileName, err := d.InitDownloadPart(u, i, progressbarName)
		if err != nil {
            d.ErrCh <- fmt.Errorf("failed to initialize download parts: %w", err)
            return
        }

		// Create Progress bar
		bar := d.CreateProgressbar(i, rangeSize, maxProgressbarNameLen, progressbarName, speed, progressBars)

		startLength := i * rangeSize
		endLength := startLength + rangeSize - 1
		if i == d.NumParts - 1 {
			endLength = size - 1
		}

		totalSize := endLength - startLength + 1

		// Create HTTP request
		resp, err := d.DownloadFileChunk(client, startLength, endLength)
		if err != nil {
            d.ErrCh <- fmt.Errorf("failed to donwload file chunk: %w", err)
            return
        }

		// Create buffer, reader and writter
		buf, reader, writer, totalBytesDownloaded, totalElapsedMilliseconds := d.CreateBufferProgressbar(resp, totalSize, bar, outputPartFile)

		// Read stream and write part file
		outputPartFile, totalBytesDownloaded, err = d.ReadStreamWriteFile(reader, writer, buf, rangeSize, totalBytesDownloaded, totalElapsedMilliseconds, speed, bar, outputPartFile, outputPartFileName)
		if err != nil {
            d.ErrCh <- fmt.Errorf("failed to read stream write to file: %w", err)
            return
        }

		// Returning buffer to pool after finished using it completely.
		utils.BufferPool.Put(buf)

        // After downloading, compute hash
        sha256HashString, err := d.ComputeHash(i, partFilesHashes, outputPartFile)
        if err != nil {
            d.ErrCh <- fmt.Errorf("failed to compute hash: %w", err)
            return
        }

		// Rename annd validate output file
		newOutputPartFileName, err := d.RenameValidateOutputFile(f, outputPartFile, outputPartFileName, sha256HashString, timestamp, totalBytesDownloaded, totalSize)
		 if err != nil {
            d.ErrCh <- fmt.Errorf("failed to rename valid output file: %w", err)
            return
        }

		// Update downloaded manifest
        d.UpdateDownloadManifest(downloadManifest, i, sha256HashString, timestamp, newOutputPartFileName)

    }(i)
}

func (d *Downloader) FetchFileInfo(client *http.Client) (int, string, string, error) {
	size, etag, hashType, err := d.GetFileInfo(client)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to get file info: %w", err)
	}
	return size, etag, hashType, nil
}

func (d *Downloader) GetFileNameAndHash(hashes map[string]string) (string, string, error) {
	parsedURL, err := url.Parse(d.URLFile)
	if err != nil {
		return "", "", fmt.Errorf("error: Invalid URL: %w", err)
	}
	fileName := path.Base(parsedURL.Path)
	hash := hashes[fileName]
	return fileName, hash, nil
}

func (d *Downloader) ManagePartDownload(client *http.Client, size int, rangeSize int, maxProgressbarNameLen int, progressbarName string, progressBars []*uiprogress.Bar, partFilesHashes []string, speed atomic.Value, downloadManifest *manifest.DownloadManifest, sem chan struct{}) {
	var wg sync.WaitGroup
	var firstError error
	wg.Add(d.NumParts)

	speeds := make([]atomic.Value, d.NumParts)
	for i := 0; i < d.NumParts; i++ {
		speeds[i] = atomic.Value{}
		speeds[i].Store("0 KB/s")
		go d.DownloadPart(client, i, rangeSize, size, sem, maxProgressbarNameLen, progressbarName, progressBars, partFilesHashes, speeds[i], downloadManifest, &wg)
	}

	go func() {
		for err := range d.ErrCh {
			if err != nil && firstError == nil { // capture only the first error
				firstError = fmt.Errorf("error captured in errChannel: %w", err)
			}
		}
	}()
	wg.Wait()
	close(d.ErrCh)  // Close the channel here after all download goroutines finish
}

func (d *Downloader) DownloadPartFiles(hashes map[string]string) (manifest.DownloadManifest, []string, int, string, string, int, string, error) {
	client, err := d.InitHTTPClient()
	if err != nil {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", err
	}

	size, etag, hashType, err := d.FetchFileInfo(client)
	if err != nil {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", err
	}

	fileName, fileHash, err := d.GetFileNameAndHash(hashes)
	if err != nil {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", err
	}

	downloadManifest := d.InitDownloadManifest(fileName, fileHash, etag, hashType, size, size/d.NumParts)

	maxProgressbarNameLen, speed, progressbarName := d.InitUI()

	uiprogress.Start()

	progressBars := make([]*uiprogress.Bar, d.NumParts)
	partFilesHashes := make([]string, d.NumParts)
	sem := make(chan struct{}, d.MaxConcurrentConnections)

	d.ManagePartDownload(client, size, size/d.NumParts, maxProgressbarNameLen, progressbarName, progressBars, partFilesHashes, speed, &downloadManifest, sem)

	uiprogress.Stop()

	firstError, ok := <-d.ErrCh
	if ok {
		return manifest.DownloadManifest{}, nil, 0, "", "", 0, "", firstError
	} else {
		fmt.Println("No errors received from goroutine")
	}

	return downloadManifest, partFilesHashes, size, etag, hashType, size/d.NumParts, fileName, nil
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
		return 0, "", "", fmt.Errorf("invalid Content-Length received from server: %w", err)
	}

	return size, etag, hashType, err
}

func (d *Downloader) ValidateInput(urlFile string, downloadOnly bool) error {
	if urlFile == "" {
		if downloadOnly {
			return fmt.Errorf("error: --download-only requires --url flag")
		} else {
			return fmt.Errorf("error: --url flag required")
		}
	}
	return nil
}

func (d *Downloader) ObtainShaSumsHashes(f *fileutils.Fileutils, shaSumsURL string) (map[string]string, error) {
	h := hasher.NewHasher(d.PartsDir, d.PrefixParts, d.Log)
	hashes, err := d.InitDownloadAndParseHashFile(h, shaSumsURL)
	if err != nil {
		return make(map[string]string), fmt.Errorf("failed to download and parse shasum file: %w", err)
	}

	return hashes, nil
}

func (d *Downloader) ProcessHash(f *fileutils.Fileutils, partsDir string, prefixParts string, shaSumsURL string, hashes map[string]string) (string, manifest.DownloadManifest, []string, int, string, string, int, string, error) {

	downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName, err := d.DownloadPartFiles(hashes)
	if err != nil {
		return "", manifest.DownloadManifest{}, []string{}, 0, "", "", 0, "", fmt.Errorf("failed to download part files: %w", err)
	}

	hash, err := f.CombinedMD5HashForPrefixedFiles(partsDir, prefixParts)
	if err != nil {
		return "", manifest.DownloadManifest{}, []string{}, 0, "", "", 0, "", fmt.Errorf("fail to obtain combined parts file hash: %w", err)
	}
	return hash, downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName, nil
}

func (d *Downloader) FilePathAndValidation(outputFile string) (string, error) {
	f := fileutils.NewFileutils(d.PartsDir, d.PrefixParts, d.Log)

	// Validate the path of output file
	message, err := f.ValidatePath(outputFile)
	if err != nil {
		return "", fmt.Errorf("found an error validating path string: %w", err)
	} else {
		d.Log.Debugw(message)
	}

	// Extract the path and filename from the output file
	filePath, _, err := f.ExtractPathAndFilename(outputFile)
	if err != nil {
		return "", fmt.Errorf("could not parse the string:%w", err)
	}

	// Validate the path of the output file
	if filePath != "" {
		err = f.ValidateCreatePath(filePath)
		if err != nil {
			return "", fmt.Errorf("found an error validating path string: %w", err)
		}
	}

	return "", nil
}

func (d *Downloader) SaveManifest(m *manifest.Manifest, downloadManifest manifest.DownloadManifest, fileName string, hash string) error {
	err := m.SaveDownloadManifest(downloadManifest, fileName, hash)
	if err != nil {
		return fmt.Errorf("failed updating the progress bar: %w", err)
	}
	return nil
}

func (d *Downloader) HandleEncryption(m *manifest.Manifest, e *encryption.Encryption, f *fileutils.Fileutils, partFilesHashes []string, fileName string, hash string) ([]byte, string, error) {
	key, err := e.CreateEncryptionKey(partFilesHashes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to obtain the encryption key: %w", err)
	}

	manifestPath, err := m.GetDownloadManifestPath(fileName, hash)
	if err != nil {
		return nil, "", fmt.Errorf("failed to obtain the path of the downloaded manifest: %w", err)
	}

	if f.PathExists(manifestPath + ".enc") {
		d.Log.Debugw("Encrypted manifest file exists. Deleting:", "file", manifestPath + ".enc")
		err := os.Remove(manifestPath + ".enc")
		if err != nil {
			return nil, "", fmt.Errorf("removing manifest file: %w", err)
		}
	}

	err = e.EncryptFile(manifestPath, key)
	if err != nil {
		return nil, "", fmt.Errorf("encrypting manifest file: %w", err)
	}
	return key, manifestPath, nil
}

func (d *Downloader) Download(shaSumsURL string, partsDir string, prefixParts string, urlFile string, downloadOnly bool, outputFile string) (manifest.DownloadManifest, map[string]string, string, []byte, int, int, string, string, error) {
	e := encryption.NewEncryption(d.PartsDir, d.PrefixParts, d.Log)
	f := fileutils.NewFileutils(d.PartsDir, d.PrefixParts, d.Log)
	m := manifest.NewManifest(d.PartsDir, d.PrefixParts, d.Log)

	err := d.ValidateInput(urlFile, downloadOnly)
    if err != nil {
        return manifest.DownloadManifest{}, make(map[string]string), "", nil, 0, 0, "", "", fmt.Errorf("failed to validate url flag string: %w", err)
    }

	hashes, err := d.ObtainShaSumsHashes(f, shaSumsURL)
    if err != nil {
        return manifest.DownloadManifest{}, make(map[string]string), "", nil, 0, 0, "", "", fmt.Errorf("failed to download and process shasums file: %w", err)
    }

    hash, downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName, err := d.ProcessHash(f, partsDir, prefixParts, shaSumsURL, hashes)
    if err != nil {
        return manifest.DownloadManifest{}, make(map[string]string), "", nil, 0, 0, "", "", fmt.Errorf("failed to process shasums file: %w", err)
    }

    if !downloadOnly {
        _, err = d.FilePathAndValidation(outputFile)
        if err != nil {
            return manifest.DownloadManifest{}, make(map[string]string), "", nil, 0, 0, "", "", fmt.Errorf("failed to validate output file path: %w", err)
        }
    }

    err = d.SaveManifest(m, downloadManifest, fileName, hash)
    if err != nil {
        return manifest.DownloadManifest{}, make(map[string]string), "", nil, 0, 0, "", "", fmt.Errorf("failed to save manifest file: %w", err)
    }

    key, manifestPath, err := d.HandleEncryption(m, e, f, partFilesHashes, fileName, hash)
    if err != nil {
        return manifest.DownloadManifest{}, make(map[string]string), "", nil, 0, 0, "", "", fmt.Errorf("failed to handle ecrypted manifest file: %w", err)
    }

	if downloadOnly {
		d.Log.Infow("Part files saved to directory", "directory", partsDir)
	}

    return downloadManifest, hashes, manifestPath, key, size, rangeSize, etag, hashType, nil
}
