package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	url      string
	numParts int
	log      *logrus.Logger
)

func init() {
	flag.StringVar(&url, "url", "", "URL of the file to download")
	flag.IntVar(&numParts, "n", 5, "Number of parts to split the download into")
	flag.Parse()

	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{})
	log.SetLevel(logrus.DebugLevel)
}

func main() {
	if len(url) == 0 {
		log.Fatal("URL is required")
	}

	log.WithField("URL", url).Debug("Creating HTTP request for URL") // Add debug output

	// Create a custom HTTP client with a timeout
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 60 * time.Second,
		},
	}

	log.Debug("Performing HTTP request") // Add debug output

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		log.Fatal("Error: ", err)
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	if res.StatusCode != http.StatusOK {
		log.Fatal("Server returned non-200 status code")
	}

	etag := res.Header.Get("Etag")
	var hashType string
	if strings.HasPrefix(etag, "W/\"") {
		hashType = "weak"
		etag = etag[3 : len(etag)-1]
	} else if strings.HasPrefix(etag, "\"") {
		hashType = "strong"
		etag = etag[1 : len(etag)-1]
	} else {
		hashType = "unknown"
	}

	log.WithFields(logrus.Fields{
		"Etag":     etag,
		"HashType": hashType,
	}).Debug("Received Etag and HashType") // Print Etag and HashType. Debug output

	size, err := strconv.Atoi(res.Header.Get("Content-Length"))
	if err != nil {
		log.Fatal("Invalid Content-Length received from server")
	}

	log.Debug("Starting download")

	var wg sync.WaitGroup
	wg.Add(numParts)

	rangeSize := size / numParts
	log.WithFields(logrus.Fields{
		"FileSize":  size,
		"RangeSize": rangeSize,
	}).Debug("Calculated File size and Range size") // Print file size and range size. . Debug output

	outFile, err := os.Create("output")
	if err != nil {
		log.Fatal("Error: ", err)
	}
	defer outFile.Close()

	for i := 0; i < numParts; i++ {
		go func(i int) {
			defer wg.Done()

			// Add delay before starting each goroutine
			time.Sleep(time.Duration(i) * time.Second)

			start := i * rangeSize
			end := start + rangeSize

			log.WithFields(logrus.Fields{
				"Start":  start,
				"End": end-1,
			}).Debug("Downloading range Start to End\n") // Add debug output

			if i == numParts-1 {
				end = size
			}

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Fatal("Error: ", err)
			}

			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end-1))
			// resp, err := http.DefaultClient.Do(req)
			resp, err := client.Do(req) // Use the custom client
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer resp.Body.Close()

			fmt.Printf("Writing to file: output.part%d\n", i+1) // Print the part being written. Debug output

			log.WithFields(logrus.Fields{
				"Number": i+1,
			}).Debug("Writing to file: output.partNumber\n") // Print the part being written. Debug output

			outFilePart, err := os.Create(fmt.Sprintf("output.part%d", i+1))
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer outFilePart.Close()

			io.Copy(outFilePart, resp.Body)
			fmt.Printf("Downloaded part %d\n", i+1)
		}(i)
	}

	wg.Wait()

	for i := 0; i < numParts; i++ {
		outFilePart, err := os.Open(fmt.Sprintf("output.part%d", i+1))
		if err != nil {
			log.Fatal("Error: ", err)
		}

		io.Copy(outFile, outFilePart)
		outFilePart.Close()

		os.Remove(fmt.Sprintf("output.part%d", i+1))
	}

	fmt.Println("File downloaded and assembled")

	fileHash, err := hashFile("output")
	if err != nil {
		log.Fatal("Error: ", err)
	}

	log.WithFields(logrus.Fields{
		"MD5":    fileHash.md5,
		"SHA1":   fileHash.sha1,
		"SHA256": fileHash.sha256,
	}).Debug("File Hashes")  // Print file hashes. Debug output

	if hashType == "strong" && (etag == fileHash.md5 || etag == fileHash.sha1 || etag == fileHash.sha256) {
		fmt.Println("File hash matches Etag")
	} else if hashType == "weak" && strings.HasPrefix(etag, fileHash.md5) {
		fmt.Println("File hash matches Etag")
	} else if hashType == "unknown" {
		fmt.Println("Unknown Etag format, cannot check hash")
	} else {
		fmt.Println("File hash does not match Etag")
	}
}

type fileHashes struct {
	md5    string
	sha1   string
	sha256 string
}

func hashFile(path string) (fileHashes, error) {
	file, err := os.Open(path)
	if err != nil {
		return fileHashes{}, err
	}
	defer file.Close()

	hMd5 := md5.New()
	hSha1 := sha1.New()
	hSha256 := sha256.New()

	if _, err := io.Copy(io.MultiWriter(hMd5, hSha1, hSha256), file); err != nil {
		return fileHashes{}, err
	}

	return fileHashes{
		md5:    hex.EncodeToString(hMd5.Sum(nil)),
		sha1:   hex.EncodeToString(hSha1.Sum(nil)),
		sha256: hex.EncodeToString(hSha256.Sum(nil)),
	}, nil
}