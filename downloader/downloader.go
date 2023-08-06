// file: downloader/downloader.go
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

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/manifest"
	"github.com/campeon23/multi-source-downloader/utils"
	"github.com/google/uuid"
	"github.com/gosuri/uiprogress"
)

type Downloader struct {
	UrlFile string 
	NumParts int 
	MaxConcurrentConnections int
	PartsDir string
	Log	*logger.Logger
}

func NewDownloader(urlFile string, numParts int, maxConcurrentConnections int, partsDir string, log *logger.Logger) *Downloader {
	return &Downloader{
		UrlFile: urlFile, 
		NumParts: numParts,
		MaxConcurrentConnections: maxConcurrentConnections,
		PartsDir: partsDir,
		Log: log,
	}
}

func (d *Downloader) DownloadPartFiles() (manifest.DownloadManifest, []string, int, string, string, int, string) {
	var hashType string

	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 60 * time.Second,
		},
	}

	d.Log.Infow("Performing HTTP request") // Add debug output

	req, err := http.NewRequest("HEAD", d.UrlFile, nil)
	if err != nil {
		d.Log.Fatal("Error: ", err)
	}

	res, err := client.Do(req)
	if err != nil {
		d.Log.Fatal("Error: ", err)
	}
	if res.StatusCode != http.StatusOK {
		d.Log.Fatal("Server returned non-200 status code")
	}

	etag := res.Header.Get("Etag")
	etag = strings.ReplaceAll(etag, "\"", "") // Remove double quotes
	
	if strings.HasPrefix(etag, "W/") {
		hashType = "weak"
		etag = etag[2:] // We've already removed the quotes, so we only need to skip the "W/"
	} else if etag != "" {
		hashType = "strong"
		// The quotes are already removed, so no need to modify the etag string
	} else {
		hashType = "unknown"
	}

	d.Log.Debugw(
		"Received Etag and HashType", 
		"etag",		etag,
		"HashType", hashType,
	) // Print Etag and HashType. Debug output

	size, err := strconv.Atoi(res.Header.Get("Content-Length"))
	if err != nil {
		d.Log.Fatal("Invalid Content-Length received from server")
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

	parsedURL, err := url.Parse(d.UrlFile)
	if err != nil {
		d.Log.Fatal("Invalid URL")
	}

	// Get the file name from the URL
	fileName := path.Base(parsedURL.Path)

	// Create and initialize the download manifest
	downloadManifest := manifest.DownloadManifest{
		Version:  "1.0",
		UUID:     uuid.New().String(),
		Filename: fileName,
		URL:      d.UrlFile,
		Etag:	  etag,
		HashType: hashType,
	}

	d.Log.Debugw("Inititalizing download manifest", "downloadManifest", downloadManifest) // Add debug output


	// Calculate the maximum length of the filenames
	maxProgressFileNameLen := 0
	var speed atomic.Value // Atomic value to handle concurrent access to speed
	speed.Store("")        // Initialize the speed variable

	// Create a new UI progress bar and start it
	uiprogress.Start()
	progressBars := make([]*uiprogress.Bar, d.NumParts)
	partFilesHashes := make([]string, d.NumParts)

	sem := make(chan struct{}, d.MaxConcurrentConnections) // maxConcurrentConnections is the limit you set

	if d.MaxConcurrentConnections == 0 {
		d.Log.Debugw("Max concurrent connections not set. Downloading all parts at once.")
	}

	for i := 0; i < d.NumParts; i++ {
		go func(i int) {
			if d.MaxConcurrentConnections != 0 {
				sem <- struct{}{} // acquire a token
				defer func() { <-sem }() // release the token
			}

			defer wg.Done()

			timestamp := time.Now().UnixNano() // UNIX timestamp with nanosecond precision

			progressFileName := fmt.Sprintf("output part %d", i+1)
			// outputPartFileName := fmt.Sprintf("output-%d.part", i+1)
			outputPartFileName := fmt.Sprintf("%soutput-%s-%d.part", d.PartsDir, uuid.New(), i+1)

			d.Log.Debugw("Debugging part files paths",
				"outputPartFileName", outputPartFileName,
				"partsDir", d.PartsDir,
			) // Add debug output

			outputPartFile, err := os.Create(outputPartFileName)
			if err != nil {
				d.Log.Fatal("Error: ", err)
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

			req, err := http.NewRequest("GET", d.UrlFile, nil)
			if err != nil {
				d.Log.Fatal("Error: ", err)
			}

			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", startLength, endLength))

			d.Log.Debugw(
				"Downloading range Start to End", 
				"Start", startLength,
				"End",	 endLength,
			) // Add debug output

			resp, err := client.Do(req) // Use the custom client
			if err != nil {
				d.Log.Fatal("Error: ", err)
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
				bytesRead, err := reader.Read(buf)
				if bytesRead > 0 {
					_, err := writer.Write(buf[:bytesRead])
					if err != nil {
						d.Log.Fatal("Error: ", err)
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
					d.Log.Fatal("Error: ", err)
				}
				startTime = time.Now() // reset start time after processing the chunk
				currentSpeed := utils.FormatSpeed(totalBytesDownloaded, totalElapsedMilliseconds)
				speed.Store(currentSpeed)
			}

			// Close and reopen the file to calculate the hash
			outputPartFile.Close()
			outputPartFile, err = os.Open(outputPartFileName)
			if err != nil {
				d.Log.Fatal("Error: ", err)
			}
			defer outputPartFile.Close()

			// Calculate the hash from the temporary part file
			h := sha256.New()
			if _, err := io.Copy(h, outputPartFile); err != nil {
				d.Log.Fatal("Error: ", err)
			}
			sha256Hash := h.Sum(nil)
			sha256HashString := hex.EncodeToString(sha256Hash[:])
			partFilesHashes[i] = sha256HashString

			// Close the file before renaming
			outputPartFile.Close()

			partFileName := fmt.Sprintf("%soutput-%s-%d.part", d.PartsDir, sha256HashString, timestamp)
			if err := os.Rename(outputPartFileName, partFileName); err != nil {
				d.Log.Fatal("Failed to rename the part file: %v", "error", err)
			}

			// Reopen the file under the new name
			outputPartFile, err = os.OpenFile(partFileName, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				d.Log.Fatal("Error: ", err)
			}
			defer outputPartFile.Close()

			if totalBytesDownloaded != int64(totalSize) {
				d.Log.Fatal("Error: expected to read more bytes")
			}

			d.Log.Infow(
				"Writing to manifest file",
			)

			// Add downloaded part info to the download manifest
			downloadManifest.DownloadedParts = append(downloadManifest.DownloadedParts, manifest.DownloadedPart{
				PartNumber: i + 1,
				FileHash:   sha256HashString,
				Timestamp:  timestamp,
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

	wg.Wait()

	// Stop the progress bar after all downloads are complete
	uiprogress.Stop()

	return downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName
}