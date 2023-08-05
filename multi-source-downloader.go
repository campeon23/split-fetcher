package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gosuri/uiprogress"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
)

var (
	maxConcurrentConnections 	int
	shaSumsURL 					string
	urlFile  					string
	numParts 					int
	verbose 					bool
	log 						*zap.SugaredLogger
)

var rootCmd = &cobra.Command{
	Use:   "multi-source-downloader",
	Short: `The downloader is a Go app that fetches files in parts concurrently, 
with options for integrity validation and connection limits.`,
	Long:  `The multiple source downloader is an application written in Go that splits the file 
to be downloaded into n parts and downloads them concurrently in an optimized manner. 
It then assembles the final file, with support for either Etag validation or Hash 
validation, to ensure file integrity. And more things...`,
	Run:   execute,
}

type fileHashes struct {
	md5    string
	sha1   string
	sha256 string
}

// Adding a new structure to represent the JSON manifest
type DownloadManifest struct {
	UUID             string                `json:"uuid"`
	Version		  	 string                `json:"version"`
	Filename         string                `json:"filename"`
	URL              string                `json:"url"`
	Etag			 string                `json:"etag"`
	HashType		 string                `json:"hash_type"`
	DownloadedParts  []DownloadedPart      `json:"downloaded_parts"`
}

type DownloadedPart struct {
	PartNumber int    `json:"part_number"`
	FileHash   string `json:"file_hash"`
	Timestamp  int64  `json:"timestamp"`
}

type progressWriter struct {
	bar *uiprogress.Bar
	w   io.Writer
}

func init() {
	// cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().IntVarP(&maxConcurrentConnections, "max-connections", "m", 0, `(Optional) Controls how many parts of the 
file are downloaded at the same time. You can set a specific number, 
or if you set it to 0, it will choose the best number for you.`)
	rootCmd.PersistentFlags().StringVarP(&shaSumsURL, "sha-sums", "s", "", `(Optional) The URL of the file containing the hashes refers to a file 
with either MD5 or SHA-256 hashes, used to verify the integrity and 
authenticity of the downloaded file.`)
	rootCmd.PersistentFlags().StringVarP(&urlFile, "url", "u", "", "URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&numParts, "num-parts", "n", 5, "(Optional) Number of parts to split the download into")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "(Optional) Output verbose logging (INFO and Debug), verbose not passed only output INFO logging.")

	viper.BindPFlag("max-connections", rootCmd.PersistentFlags().Lookup("max-connections"))
	viper.BindPFlag("sha-sums", rootCmd.PersistentFlags().Lookup("sha-sums"))
	viper.BindPFlag("url", rootCmd.PersistentFlags().Lookup("url"))
	viper.BindPFlag("num-parts", rootCmd.PersistentFlags().Lookup("num-parts"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initLogger(verbose bool) {
	var cfg zap.Config
	if verbose {
		cfg = zap.NewDevelopmentConfig() // More verbose logging
	} else {
		cfg = zap.NewProductionConfig() // Only INFO level and above
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync() // Flushes buffer, if any
	log = logger.Sugar()
}

func downloadAndParseHashFile() (map[string]string, error) {
	resp, err := http.Get(shaSumsURL)
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

func getDownloadManifestPath() string {
	if runtime.GOOS == "windows" {
		user, err := user.Current()
		if err != nil {
			log.Fatal("Error fetching user information: ", err)
		}
		return filepath.Join(user.HomeDir, "Appdata", ".multi-source-downloader", ".file_parts_manifest.json")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", ".multi-source-downloader", ".file_parts_manifest.json")
}

func saveDownloadManifest(manifest DownloadManifest) {
	log.Debugw("Initializing Application Directory")

	manifestPath := getDownloadManifestPath()

	// Ensure the directory exists
	manifestDir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		log.Fatal("Error creating config directory: ", err)
	}

	// Debugging: Check if the directory was created
	if pathExists(manifestDir) {
		log.Debugw("Application Directory created successfully", "directory", manifestDir)
	} else {
		log.Warnw("Directory not found", "directory", manifestDir)
	}

	// Before saving the manifest file, check if the file exists and delete it
	if pathExists(manifestPath) {
		log.Debugw("Manifest file exists. Deleting:", "file", manifestPath)
		err := os.Remove(manifestPath)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Infow("Manifest file not found", "file: ", manifestPath)
	}

	file, err := os.Create(manifestPath)
	if err != nil {
		log.Fatal("Error creating manifest file: ", err)
	}
	defer file.Close()

	// Debugging: Check if the file was created
	if _, err := os.Stat(manifestPath); err == nil {
		log.Debugw("File created successfully", "file", manifestPath)
	} else {
		log.Warnw("File not found", "file", manifestPath)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(manifest); err != nil {
		log.Fatal("Error encoding manifest JSON: ", err)
	}

	// On Windows, make the file hidden
	if runtime.GOOS == "windows" {
		cmd := fmt.Sprintf("attrib +h %s", manifestPath)
		if err := exec.Command("cmd", "/C", cmd).Run(); err != nil {
			log.Fatal("Error hiding manifest file: ", err)
		}
	}
}

func createEncryptionKey(strings []string) ([]byte, error) {
	// Sort the strings in reverse order
	sort.Sort(sort.Reverse(sort.StringSlice(strings)))

	// Concatenate the sorted strings
	var buffer bytes.Buffer
	for _, str := range strings {
		buffer.WriteString(str)
	}

	// Use the concatenated string with PBKDF2 to derive a key
	salt := []byte("your-salt") // Use a constant or random salt as needed
	key := pbkdf2.Key([]byte(buffer.Bytes()), salt, 4096, 32, sha256.New) // Pass the buffer as a byte slice

	return key, nil
}

// encryptFile encrypts the file with the given key and writes the encrypted data to a new file
func encryptFile(filename string, key []byte) error {
	log.Info("Initializing ecryption of manifest file.")
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)

	paddingLength := aes.BlockSize - len(plaintext)%aes.BlockSize
	padding := make([]byte, paddingLength)
	for i := range padding {
		padding[i] = byte(paddingLength)
	}
	plaintext = append(plaintext, padding...)

	ciphertext := make([]byte, len(plaintext))
	encrypter.CryptBlocks(ciphertext, plaintext)

	encryptedFilename := filename + ".enc"
	encryptedFile, err := os.Create(encryptedFilename)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	encryptedFile.Write(iv)
	encryptedFile.Write(ciphertext)

	log.Debugw("File encrypted successfully and saved as:", 
		"encryptedFilename", encryptedFilename,
	)

	err = os.Remove(filename)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func decryptFile(encryptedFilename string, key []byte, toDisk bool) ([]byte, error) {
	encryptedFile, err := os.Open(encryptedFilename)
	if err != nil {
		return nil, err
	}
	defer encryptedFile.Close()

	iv := make([]byte, aes.BlockSize)
	_, err = encryptedFile.Read(iv)
	if err != nil {
		return nil, err
	}

	ciphertext, err := io.ReadAll(encryptedFile)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	paddingLength := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-paddingLength]

	if toDisk {
		decryptedFilename := strings.TrimSuffix(encryptedFilename, ".enc")
		decryptedFile, err := os.Create(decryptedFilename)
		if err != nil {
			return nil, err
		}
		defer decryptedFile.Close()

		_, err = decryptedFile.Write(plaintext)
		if err != nil {
			return nil, err
		}

		log.Debugw("File decrypted successfully and saved as:",
			"decryptedFilename", decryptedFilename,
		)

		return nil, nil

	} else {
		return plaintext, nil
	}
}

// Function to calculate the SHA-256 hash of a file
func calculateSHA256(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func pathExists(path string) bool {
    _, err := os.Stat(path)
    return !os.IsNotExist(err)
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.bar.Set(pw.bar.Current() + n)
	return pw.w.Write(p)
}

func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatPercentage(current, total int64) string {
	percentage := float64(current) / float64(total) * 100
	return fmt.Sprintf("%.1f%%", percentage)
}

func formatSpeed(bytes int64, totalMilliseconds int64) string {
	if totalMilliseconds == 0 {
		totalMilliseconds = 1
	}
	speed := float64(bytes) / (float64(totalMilliseconds) / float64(1000*1000)) // B/s
	const unit = 1024

	if speed < unit {
		return fmt.Sprintf("| %.2f B/s", speed)
	}
	div, exp := unit, 0
	for n := speed / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	unitPrefix := fmt.Sprintf("%ciB/s", "KMGTPE"[exp])
	return fmt.Sprintf("| %.2f %s", speed/float64(div), unitPrefix)
}

// Define a buffer pool globally to reuse buffers
var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096) // Fixed buffer size for efficient memory usage
	},
}

func run(maxConcurrentConnections int, shaSumsURL string, urlFile string, numParts int){
	hashes := make(map[string]string)
	if len(shaSumsURL) != 0 {
		var err error
		log.Info(
			"Initializing HTTP request",
		) // Add info output
		log.Debugw(
			"Creating HTTP request for URL",
			"URL", shaSumsURL,
		) // Add debug output
		hashes, err = downloadAndParseHashFile()
		if err != nil {
			log.Fatal("Error: ", err)
		}
	}

	if len(urlFile) == 0 {
		log.Fatal("URL is required")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 60 * time.Second,
		},
	}

	log.Info("Performing HTTP request") // Add debug output

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

	log.Info("Starting download")

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

	// Create and initialize the download manifest
	downloadManifest := DownloadManifest{
		Version:  "1.0",
		UUID:     uuid.New().String(),
		Filename: fileName,
		URL:      urlFile,
		Etag:	  etag,
		HashType: hashType,
	}

	log.Debugw("Inititalizing download manifest", "downloadManifest", downloadManifest) // Add debug output

	outFile, err := os.Create(fileName)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	defer outFile.Close()

	// Calculate the maximum length of the filenames
	maxProgressFileNameLen := 0
	var speed atomic.Value // Atomic value to handle concurrent access to speed
	speed.Store("")        // Initialize the speed variable

	// Create a new UI progress bar and start it
	uiprogress.Start()
	progressBars := make([]*uiprogress.Bar, numParts)
	partFilesHashes := make([]string, numParts)

	sem := make(chan struct{}, maxConcurrentConnections) // maxConcurrentConnections is the limit you set

	if maxConcurrentConnections == 0 {
		log.Debugw("Max concurrent connections not set. Downloading all parts at once.")
	}

	for i := 0; i < numParts; i++ {
		go func(i int) {
			if maxConcurrentConnections != 0 {
				sem <- struct{}{} // acquire a token
				defer func() { <-sem }() // release the token
			}

			defer wg.Done()

			timestamp := time.Now().UnixNano() // UNIX timestamp with nanosecond precision

			progressFileName := fmt.Sprintf("output part %d", i+1)
			outputPartFileName := fmt.Sprintf("output-%d.part", i+1)
			outputPartFile, err := os.Create(outputPartFileName)
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer outputPartFile.Close()

			if len(progressFileName) > maxProgressFileNameLen {
				maxProgressFileNameLen = len(progressFileName)
			}

			// Create a progress bar
			bar := uiprogress.AddBar(rangeSize).PrependElapsed()

			// var speed string
			
			// Set the progress bar details
			bar.PrependFunc(func(b *uiprogress.Bar) string {
				return fmt.Sprintf("%-*s | %s | %s", maxProgressFileNameLen, progressFileName, formatFileSize(int64(b.Current())), formatFileSize(int64(rangeSize)))
			})
			bar.AppendFunc(func(b *uiprogress.Bar) string {
				return fmt.Sprintf("%s %s", formatPercentage(int64(b.Current()), int64(rangeSize)), speed.Load().(string))
			})

			// Save this progress bar in the progressBars slice
			progressBars[i] = bar

			startLength := i * rangeSize
			endLength := startLength + rangeSize - 1
			if i == numParts - 1 {
				endLength = size - 1
			}

			totalSize := endLength - startLength + 1

			req, err := http.NewRequest("GET", urlFile, nil)
			if err != nil {
				log.Fatal("Error: ", err)
			}

			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", startLength, endLength))

			log.Debugw(
				"Downloading range Start to End", 
				"Start", startLength,
				"End",	 endLength,
			) // Add debug output

			resp, err := client.Do(req) // Use the custom client
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer resp.Body.Close()

			buf := bufferPool.Get().([]byte) // Get a buffer from the pool
			defer func() { 
				bufferPool.Put(buf) 
			}() // Return the buffer to the pool when done

			reader := io.LimitReader(resp.Body, int64(totalSize))

			// Create a custom writer to track the progress
			writer := &progressWriter{
				bar: bar,
				w:   outputPartFile,
			}

			totalBytesDownloaded := int64(0)
			totalElapsedMilliseconds := int64(0)

			startTime := time.Now() // record start time of reading chunk
			for {
				bytesRead, err := reader.Read(buf)
				if bytesRead > 0 {
					_, err := writer.Write(buf[:bytesRead])
					if err != nil {
						log.Fatal("Error: ", err)
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
					log.Fatal("Error: ", err)
				}
				startTime = time.Now() // reset start time after processing the chunk
				currentSpeed := formatSpeed(totalBytesDownloaded, totalElapsedMilliseconds)
				speed.Store(currentSpeed)
			}

			// Close and reopen the file to calculate the hash
			outputPartFile.Close()
			outputPartFile, err = os.Open(outputPartFileName)
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer outputPartFile.Close()

			// Calculate the hash from the temporary part file
			h := sha256.New()
			if _, err := io.Copy(h, outputPartFile); err != nil {
				log.Fatal("Error: ", err)
			}
			sha256Hash := h.Sum(nil)
			sha256HashString := hex.EncodeToString(sha256Hash[:])
			partFilesHashes[i] = sha256HashString

			// Close the file before renaming
			outputPartFile.Close()

			// Rename the temporary part file
			partFileName := fmt.Sprintf("output-%s-%d.part", sha256HashString, timestamp)
			if err := os.Rename(outputPartFileName, partFileName); err != nil {
				log.Fatal("Error: ", err)
			}

			// Reopen the file under the new name
			outputPartFile, err = os.OpenFile(partFileName, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer outputPartFile.Close()

			if totalBytesDownloaded != int64(totalSize) {
				log.Fatal("Error: expected to read more bytes")
			}

			log.Info(
				"Writing to manifest file",
			)

			// Add downloaded part info to the download manifest
			downloadManifest.DownloadedParts = append(downloadManifest.DownloadedParts, DownloadedPart{
				PartNumber: i + 1,
				FileHash:   sha256HashString,
				Timestamp:  timestamp,
			})

			log.Debugw(
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

	// Saving the download manifest
	saveDownloadManifest(downloadManifest)

	// Obtain the encryption key
	key, err := createEncryptionKey(partFilesHashes)
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	// Encrypt the download manifest
	manifestPath := getDownloadManifestPath()

	// Before encrypting the manifest file, check if the encrypted file exists and delete it
	if pathExists(manifestPath + ".enc") {
		log.Debugw("Encrypted manifest file exists. Deleting:", "file", manifestPath + ".enc")
		err := os.Remove(manifestPath + ".enc")
		if err != nil {
			log.Fatal(err)
		}
	}

	err = encryptFile(manifestPath, key)
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	// Decrypt the download manifest
	var decryptedContent []byte
	decryptedContent, err = decryptFile(manifestPath + ".enc", key, false)
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	// Decode the JSON content into a map
	var manifest DownloadManifest // The JSON structure defined above as DownloadManifest
	err = json.Unmarshal(decryptedContent, &manifest)
	if err != nil {
		log.Fatal("Error decoding decrypted content: ", err)
	}

	// Clean memory after decoding content
	decryptedContent = nil

	// Search for all output-* files in the current directory 
	//	to proceed to assemble the final file
	files, err := filepath.Glob("output-*")
	if err != nil {
		log.Fatal("Error: ", err)
	}

	sort.Slice(files, func(i, j int) bool {
		hashI, err := calculateSHA256(files[i])
		if err != nil {
			log.Fatal("Error calculating hash: ", err)
		}
		hashJ, err := calculateSHA256(files[j])
		if err != nil {
			log.Fatal("Error calculating hash: ", err)
		}

		// Get the part numbers from the .file_parts_manifest.json file
		numI, numJ := -1, -1
		for _, part := range manifest.DownloadedParts {
			if part.FileHash == hashI {
				numI = part.PartNumber
			}
			if part.FileHash == hashJ {
				numJ = part.PartNumber
			}
		}

		// Compare the part numbers to determine the sorting order
		return numI < numJ
	})


	// Iterate through `files` and read and combine them in the sorted order
	for i, file := range files {
		log.Debugw(
			"Downloaded part", 
			"part file",	i+1,
			"file", 		file,
		) // Print the part being assembled. Debug output
		partFile, err := os.Open(file)
		if err != nil {
			log.Fatal("Error: ", err)
		}

		copied, err := io.Copy(outFile, partFile)
		if err != nil {
			log.Fatal("Error: ", err)
		}

		if i != numParts-1 && copied != int64(rangeSize) {
			log.Fatal("Error: File part not completely copied")
		} else if i == numParts-1 && copied != int64(size)-int64(rangeSize)*int64(numParts-1) {
			log.Fatal("Error: Last file part not completely copied")
		}

		partFile.Close()
		// Remove manifest file and leave only the encrypted one
		err = os.Remove(file)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Info("File downloaded and assembled")


	fileHash, err := hashFile(fileName)
	if err != nil {
		log.Fatal("Error: ", err)
	}

	log.Debugw(
		"File Hashes", 
		"File",   			fileName,
		"sha SUMS hash",   	hashes[fileName],
		"MD5",    			fileHash.md5,
		"SHA1",   			fileHash.sha1,
		"SHA256", 			fileHash.sha256,
	)  // Print file hashes. Debug output

	// Validate the assembled file integrity and authenticity
	if hashType == "strong" && (etag == fileHash.md5 || etag == fileHash.sha1 || etag == fileHash.sha256) {
		log.Info("File hash matches Etag obtained from server (strong hash)")
	} else if hashType == "weak" && strings.HasPrefix(etag, fileHash.md5) {
		log.Info("File hash matches Etag obtained from server (weak hash))")
	} else if hashType == "unknown" {
		log.Info("Unknown Etag format, cannot check hash")
	} else if hash, ok := hashes[fileName]; ok {
		if hash == fileHash.sha256 {
			log.Info("File hash matches hash from SHA sums file")
		} else {
			log.Info("File hash does not match hash from SHA sums file")
		}
	} else {
		log.Info("File hash does not match Etag")
	}
}

func execute(cmd *cobra.Command, args []string) {
	if urlFile == "" {
		log.Fatal("Error: the --url flag is required")
	}
	initLogger(verbose) // Call this before calling run
	run(maxConcurrentConnections, shaSumsURL, urlFile, numParts)
}

func main() {
	// calls the Execute method on the rootCmd object, which is likely an instance of
	// a Cobra command. The Execute method runs the CLI, parsing the command-line 
	// arguments and running the appropriate subcommands or functions as defined in 
	// the program.
	if err := rootCmd.Execute(); err != nil {
		log.Fatal("Error: ", err)
	}
}