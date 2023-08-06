package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gosuri/uiprogress"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/campeon23/multi-source-downloader/encryption"
	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/manifest"
	"github.com/campeon23/multi-source-downloader/utils"
)

var (
	maxConcurrentConnections 	int
	shaSumsURL 					string
	urlFile  					string
	numParts 					int
	partsDir 					string
	keepParts 					bool
	verbose 					bool
	log 						*logger.Logger // Declare at package level if you want to use the logger across different functions in this package
)

var rootCmd = &cobra.Command{
	Use:   "multi-source-downloader",
	Short: `The downloader is a Go app that fetches files in parts concurrently, 
with options for integrity validation and connection limits.`,
	Long:  `The multiple source downloader is an application written in Go that splits the file 
to be downloaded into n parts and downloads them concurrently in an optimized manner. 
It then assembles the final file, with support for either Etag validation or Hash 
validation, to ensure file integrity. And more things...`,
	Run:   func(cmd *cobra.Command, args []string) {
		// Retrieve the values of your flags
		partsDir = viper.GetString("parts-dir")
		keepParts = viper.GetBool("keep-parts")
		
		// Process the partsDir value
		processPartsDir()
		// Execute the main function
		execute(cmd, args)
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().IntVarP(&maxConcurrentConnections, "max-connections", "m", 0, `(Optional) Controls how many parts of the 
file are downloaded at the same time. You can set a specific number, 
or if you set it to 0, it will choose the best number for you.`)
	rootCmd.PersistentFlags().StringVarP(&shaSumsURL, "sha-sums", "s", "", `(Optional) The URL of the file containing the hashes refers to a file 
with either MD5 or SHA-256 hashes, used to verify the integrity and 
authenticity of the downloaded file.`)
	rootCmd.PersistentFlags().StringVarP(&urlFile, "url", "u", "", "(Required) URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&numParts, "num-parts", "n", 5, "(Optional) Number of parts to split the download into")
	rootCmd.PersistentFlags().StringVarP(&partsDir, "parts-dir", "d", "", "(Optional) The directory to save the parts files")
	rootCmd.PersistentFlags().BoolVarP(&keepParts, "keep-parts", "k", false, "(Optional) Whether to keep the parts files after assembly")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, `(Optional) Output verbose logging (INFO and Debug), verbose not passed
only output INFO logging.`)

	viper.BindPFlag("max-connections", rootCmd.PersistentFlags().Lookup("max-connections"))
	viper.BindPFlag("sha-sums", rootCmd.PersistentFlags().Lookup("sha-sums"))
	viper.BindPFlag("url", rootCmd.PersistentFlags().Lookup("url"))
	viper.BindPFlag("num-parts", rootCmd.PersistentFlags().Lookup("num-parts"))
	viper.BindPFlag("parts-dir", rootCmd.PersistentFlags().Lookup("parts-dir"))
	viper.BindPFlag("keep-parts", rootCmd.PersistentFlags().Lookup("keep-parts"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}

func processPartsDir() {
	if partsDir == "" {
		var err error
		partsDir, err = os.Getwd()
		if err != nil {
			log.Fatal("Failed to get current directory: ", err.Error())
		}
	} else {
		// If the input does not look like a path, add it to the current directory
		if !filepath.IsAbs(partsDir) && !strings.HasPrefix(partsDir, "./") {
			partsDir = "./" + partsDir
		}
	}

	// If the partsDir doesn't end with a slash, add it 
	if !strings.HasSuffix(partsDir, string(os.PathSeparator)) {
		partsDir += string(os.PathSeparator)
	}

	fmt.Printf("Debugging partsDir: %s\n", partsDir) 

	// Create the directory if it doesn't exist
	if _, err := os.Stat(partsDir); os.IsNotExist(err) {
		err = os.MkdirAll(partsDir, os.ModePerm)
		if err != nil {
			log.Fatal("Failed to create directory: ", err.Error())
		}
	}
}

func downloadPartFiles(urlFile string, numParts int, maxConcurrentConnections int) (manifest.DownloadManifest, []string, int, string, string, int, string) {
	var hashType string

	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 60 * time.Second,
		},
	}

	log.Infow("Performing HTTP request") // Add debug output

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
	
	log.Infow("Starting download")

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
	downloadManifest := manifest.DownloadManifest{
		Version:  "1.0",
		UUID:     uuid.New().String(),
		Filename: fileName,
		URL:      urlFile,
		Etag:	  etag,
		HashType: hashType,
	}

	log.Debugw("Inititalizing download manifest", "downloadManifest", downloadManifest) // Add debug output


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
			// outputPartFileName := fmt.Sprintf("output-%d.part", i+1)
			outputPartFileName := fmt.Sprintf("%soutput-%s-%d.part", partsDir, uuid.New(), i+1)

			log.Debugw("Debugging part files paths",
				"outputPartFileName", outputPartFileName,
				"partsDir", partsDir,
			) // Add debug output

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
				currentSpeed := utils.FormatSpeed(totalBytesDownloaded, totalElapsedMilliseconds)
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

			partFileName := fmt.Sprintf("%soutput-%s-%d.part", partsDir, sha256HashString, timestamp)
			if err := os.Rename(outputPartFileName, partFileName); err != nil {
				log.Fatal("Failed to rename the part file: %v", "error", err)
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

			log.Infow(
				"Writing to manifest file",
			)

			// Add downloaded part info to the download manifest
			downloadManifest.DownloadedParts = append(downloadManifest.DownloadedParts, manifest.DownloadedPart{
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

	return downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName
}

func assembleFileFromParts(partsDir string, manifest manifest.DownloadManifest, outFile *os.File, numParts int, rangeSize int, size int, keepParts bool, hasher hasher.Hasher) {
    // Search for all output-* files in the current directory 
	//	to proceed to assemble the final file
	files, err := filepath.Glob(partsDir + "output-*")
	if err != nil {
		log.Fatal("Error: ", err)
	}

	sort.Slice(files, func(i, j int) bool {
		hashI, err := hasher.CalculateSHA256(files[i])
		if err != nil {
			log.Fatal("Calculating hash: ", "error", err.Error())
		}
		hashJ, err := hasher.CalculateSHA256(files[j])
		if err != nil {
			log.Fatal("Calculating hash: ", "error", err.Error())
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
		if !keepParts { // If keepParts is false, remove the part file
			// Remove manifest file and leave only the encrypted one
			err = os.Remove(file)
			if err != nil {
				log.Fatal("Removing part file: ", "error", err.Error())
			}
		}
	}

	log.Infow("File downloaded and assembled")
}

func run(maxConcurrentConnections int, shaSumsURL string, urlFile string, numParts int, partsDir string, keepParts bool){
	h := hasher.NewHasher(log)
	m := manifest.NewManifest(log)
	e := encryption.NewEncryption(log)

	hashes := make(map[string]string)
	if len(shaSumsURL) != 0 {
		var err error
		log.Infow(
			"Initializing HTTP request",
		) // Add info output
		log.Debugw(
			"Creating HTTP request for URL",
			"URL", shaSumsURL,
		) // Add debug output
		hashes, err = h.DownloadAndParseHashFile(shaSumsURL)
		if err != nil {
			log.Fatal("Downloading and/or parsing file: ", "error", err.Error())
		}
	}

	if len(urlFile) == 0 {
		log.Fatal("URL is required")
	}

	downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName := downloadPartFiles(urlFile, numParts, maxConcurrentConnections)

	// Create the final file we want to assemble
	outFile, err := os.Create(fileName)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	defer outFile.Close()

	// Saving the download manifest
	m.SaveDownloadManifest(downloadManifest)

	// Obtain the encryption key
	key, err := encryption.CreateEncryptionKey(partFilesHashes)
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	// Get the path to the download manifest
	manifestPath := m.GetDownloadManifestPath()

	// Before encrypting the manifest file, check if the encrypted file exists and delete it
	if fileutils.PathExists(manifestPath + ".enc") {
		log.Debugw("Encrypted manifest file exists. Deleting:", "file", manifestPath + ".enc")
		err := os.Remove(manifestPath + ".enc")
		if err != nil {
			log.Fatal("Removing manifest file: ", "error", err.Error())
		}
	}

	// Encrypt the download manifest
	err = e.EncryptFile(manifestPath, key)
	if err != nil {
		log.Fatal("Encrypting manifest file: ", "error", err.Error())
		return
	}

	// Decrypt the downloaded manifest
	var decryptedContent []byte
	decryptedContent, err = e.DecryptFile(manifestPath + ".enc", key, false)
	if err != nil {
		log.Fatal("Decrypting manifest file: ", "error:", err.Error())
		return
	}

	// Decode the JSON content into a map
	var manifest manifest.DownloadManifest // The JSON structure defined above as DownloadManifest
	err = json.Unmarshal(decryptedContent, &manifest)
	if err != nil {
		log.Fatal("Decoding decrypted content: ", "error", err.Error())
	}

	// Clean memory after decoding content
	decryptedContent = nil

	// Assemble the file from the downloaded parts
	assembleFileFromParts(partsDir, downloadManifest, outFile, numParts, rangeSize, size, keepParts, hasher.Hasher{})

	if !keepParts { // If keepParts is false, remove the part file
		// If partsDir was provided
		if partsDir != "" {
			// Remove the directory and all its contents
			err = os.RemoveAll(partsDir)
			if err != nil {
				log.Fatal("Failed to remove directory: ", err.Error())
			}
		}
	}

	fileHash, err := hasher.HashFile(fileName)
	if err != nil {
		log.Fatal("Error: ", err)
	}

	log.Debugw(
		"File Hashes", 
		"File",   			fileName,
		"sha SUMS hash",   	hashes[fileName],
		"MD5",    			fileHash.Md5,
		"SHA1",   			fileHash.Sha1,
		"SHA256", 			fileHash.Sha256,
	)  // Print file hashes. Debug output

	// Validate the assembled file integrity and authenticity
	if hashType == "strong" && (etag == fileHash.Md5 || etag == fileHash.Sha1 || etag == fileHash.Sha256) {
		log.Infow("File hash matches Etag obtained from server (strong hash)")
	} else if hashType == "weak" && strings.HasPrefix(etag, fileHash.Md5) {
		log.Infow("File hash matches Etag obtained from server (weak hash))")
	} else if hashType == "unknown" {
		log.Infow("Unknown Etag format, cannot check hash")
	} else if hash, ok := hashes[fileName]; ok {
		if hash == fileHash.Sha256 {
			log.Infow("File hash matches hash from SHA sums file")
		} else {
			log.Infow("File hash does not match hash from SHA sums file")
		}
	} else {
		log.Infow("File hash does not match Etag")
	}
}

func execute(cmd *cobra.Command, args []string) {
	log = logger.InitLogger(verbose) // Keep track of returned logger
    log.Infow("Logger initialized")
	if urlFile == "" {
		log.Fatal("Error: the --url flag is required")
	}
	run(maxConcurrentConnections, shaSumsURL, urlFile, numParts, partsDir, keepParts)
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