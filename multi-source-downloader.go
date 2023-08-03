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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

var (
	hashFileURL string
	urlFile  	string
	numParts 	int
	log *zap.SugaredLogger
)

func init() {
	flag.StringVar(&hashFileURL, "hashes", "", "URL of the file containing the hashes")
	flag.StringVar(&urlFile, "url", "", "URL of the file to download")
	flag.IntVar(&numParts, "n", 5, "Number of parts to split the download into")
	flag.Parse()

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync() // Flushes buffer, if any
	log = logger.Sugar()
}

func downloadAndParseHashFile() (map[string]string, error) {
	resp, err := http.Get(hashFileURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	hashes := make(map[string]string)
	for _, line := range lines {
		parts := strings.SplitN(line, "*", 2)
		log.Debugw(
			"Parsing content from hashes file.", 
			"lenght", len(parts), 
			"parts", parts,
		) // Add debug output
		if len(parts) != 2 {
			// return nil, fmt.Errorf("Invalid line in hash file: %s", line)
			continue
		}

		hash := strings.TrimSpace(parts[0])
		fileName := strings.TrimSpace(parts[1])

		hashes[fileName] = hash
	}

	log.Debugw(
		"Obtaining hashes from file.", 
		"hashes", hashes,
	) // Add debug output

	return hashes, nil
}

func generateETag(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
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

func main() {

	hashes := make(map[string]string)
	if len(hashFileURL) != 0 {
		var err error
		log.Debugw(
			"Creating HTTP request for URL",
			"URL", hashFileURL,
		) // Add debug output
		hashes, err = downloadAndParseHashFile()
		if err != nil {
			log.Fatal("Error: ", err)
		}
	}

	if len(urlFile) == 0 {
		log.Fatal("URL is required")
	}

	log.Debugw(
		"Creating HTTP request for URL",
		"URL", urlFile,
	) // Add debug output

	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 60 * time.Second,
		},
	}

	log.Debug("Performing HTTP request") // Add debug output

	req, err := http.NewRequest("HEAD", urlFile, nil)
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
	etag = strings.ReplaceAll(etag, "\"", "") // Remove double quotes
	var hashType string
	if strings.HasPrefix(etag, "W/") {
		hashType = "weak"
		etag = etag[2:] // We've already removed the quotes, so we only need to skip the "W/"
	} else if etag != "" {
		hashType = "strong"
		// The quotes are already removed, so no need to modify the etag string
	} else {
		hashType = "unknown"
	}

	log.Debugw(
		"Received Etag and HashType", 
		"etag",		etag,
		"HashType", hashType,
	) // Print Etag and HashType. Debug output

	size, err := strconv.Atoi(res.Header.Get("Content-Length"))
	if err != nil {
		log.Fatal("Invalid Content-Length received from server")
	}

	log.Debug("Starting download")

	var wg sync.WaitGroup
	wg.Add(numParts)

	rangeSize := size / numParts

	log.Debugw(
		"Calculated File size and Range size",
		"FileSize",  size,
		"RangeSize", rangeSize,
	) // Print file size and range size. . Debug output

	parsedURL, err := url.Parse(urlFile)
	if err != nil {
		log.Fatal("Invalid URL")
	}

	// Get the file name from the URL
	fileName := path.Base(parsedURL.Path)

	// Computing the MD5 hash
	md5HashFileName := md5.Sum([]byte(fileName))

	// Converting the hash to a hexadecimal string
	md5HashString := hex.EncodeToString(md5HashFileName[:])

	outFile, err := os.Create(fileName)
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
			end := start + rangeSize - 1
			if i == numParts-1 {
				end = size - 1
			}

			req, err := http.NewRequest("GET", urlFile, nil)
			if err != nil {
				log.Fatal("Error: ", err)
			}

			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

			log.Debugw(
				"Downloading range Start to End", 
				"Start", start,
				"End",	 end,
			) // Add debug output

			resp, err := client.Do(req) // Use the custom client
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer resp.Body.Close()

			timestamp := time.Now().UnixNano() // UNIX timestamp with nanosecond precision

			log.Debugw(
				"Writing to file: part-",
				"md5 hash string", md5HashString,
				"timestamp", timestamp,
			) // Print the md5 hash string and the timestamp being written. Debug output

			// outFilePart, err := os.Create(fmt.Sprintf("part-%s-%d", md5HashString, timestamp))
			outFilePart, err := os.Create(fmt.Sprintf("part-%s-%d-%d", md5HashString, i, timestamp))

			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer outFilePart.Close()

			copied, err := io.Copy(outFilePart, resp.Body)
			if err != nil {
				log.Fatal("Error: ", err)
			}
			if copied != int64(end-start+1) {
				log.Fatal("Error: File part not completely copied")
			}

			log.Debugw(
				"Downloaded part",
				"part file",			i+1,
				"md5 hash string", 		md5HashString, 
				"timestamp",	timestamp,
				"fileName", outFilePart,
			) // Print the part being written. Debug output
		}(i)
	}

	wg.Wait()

	files, err := filepath.Glob("part-*")
	if err != nil {
		log.Fatal("Error: ", err)
	}

	sort.Slice(files, func(i, j int) bool {
		// Extract the part number from the filenames
		partI := strings.Split(files[i], "-")[2]
		partJ := strings.Split(files[j], "-")[2]

		// Convert the extracted part numbers to integers
		numI, err := strconv.Atoi(partI)
		if err != nil {
			log.Fatal("Error parsing part number: ", err)
		}
		numJ, err := strconv.Atoi(partJ)
		if err != nil {
			log.Fatal("Error parsing part number: ", err)
		}

		log.Debugw("Extracting part numbers from files",
			"partI", partI,
			"partJ", partJ,
			"numI", numI,
			"numJ", numJ,
		)

		// Compare the part numbers to determine the sorting order
		return numI < numJ
	})


	// Now you can iterate through `files` and read and combine them in the sorted order

	for i, file := range files {
		log.Debugw(
			"Downloaded part", 
			"part file",	i+1,
			"file", 		file,
		) // Print the part being assembled. Debug output
		outFilePart, err := os.Open(file)
		if err != nil {
			log.Fatal("Error: ", err)
		}

		copied, err := io.Copy(outFile, outFilePart)
		if err != nil {
			log.Fatal("Error: ", err)
		}

		if copied != int64(rangeSize) && i != numParts-1 {
			log.Fatal("Error: File part not completely copied")
		}

		outFilePart.Close()
		os.Remove(file)
	}

	log.Debug("File downloaded and assembled")


	fileHash, err := hashFile(fileName)
	if err != nil {
		log.Fatal("Error: ", err)
	}

	log.Debugw(
		"File Hashes", 
		"MD5",    fileHash.md5,
		"SHA1",   fileHash.sha1,
		"SHA256", fileHash.sha256,
	)  // Print file hashes. Debug output

	if hashType == "strong" && (etag == fileHash.md5 || etag == fileHash.sha1 || etag == fileHash.sha256) {
		log.Debug("File hash matches Etag")
	} else if hashType == "weak" && strings.HasPrefix(etag, fileHash.md5) {
		log.Debug("File hash matches Etag")
	} else if hashType == "unknown" {
		log.Debug("Unknown Etag format, cannot check hash")
	} else {
		log.Debug("File hash does not match Etag")
	}

	etagFile, err := generateETag(fileName)
	if err != nil {
		panic(err)
	}

	log.Debugw(
		"File Hashes", 
		"File",   	fileName,
		"Hash",   	hashes[fileName],
		"SHA256", 	fileHash.sha256,
		"ETag",		etagFile,
	)  // Print file hashes. Debug output

	// Check if the file hash matches the one in the hash file
	if hash, ok := hashes[fileName]; ok {
		// if hash != fileHash.md5 && hash != fileHash.sha1 && hash != fileHash.sha256 {
		if hash != fileHash.sha256 {
			log.Debug("File hash does not match hash from hash file")
		} else {
			log.Debug("File hash matches hash from hash file")
		}
	}
}