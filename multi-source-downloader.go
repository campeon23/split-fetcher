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
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
)

var (
	maxConcurrentConnections 	int
	hashFileURL 				string
	urlFile  					string
	numParts 					int
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

// Adding a new structure to represent the JSON configuration
type DownloadConfig struct {
	UUID             string                `json:"uuid"`
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

func init() {
	// cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().IntVarP(&maxConcurrentConnections, "max-connections", "m", 0, `(Optional) Controls how many parts of the 
file are downloaded at the same time. You can set a specific number, 
or if you set it to 0, it will choose the best number for you.`)
	rootCmd.PersistentFlags().StringVarP(&hashFileURL, "integrity-hashes", "i", "", `(Optional) The URL of the file containing the hashes refers to a file 
with either MD5 or SHA-256 hashes, used to verify the integrity and 
authenticity of the downloaded file.`)
	rootCmd.PersistentFlags().StringVarP(&urlFile, "url", "u", "", "URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&numParts, "num-parts", "n", 5, "(Optional) Number of parts to split the download into")

	viper.BindPFlag("max-connections", rootCmd.PersistentFlags().Lookup("max-connections"))
	viper.BindPFlag("integrity-hashes", rootCmd.PersistentFlags().Lookup("integrity-hashes"))
	viper.BindPFlag("url", rootCmd.PersistentFlags().Lookup("url"))
	viper.BindPFlag("num-parts", rootCmd.PersistentFlags().Lookup("num-parts"))

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

func getDownloadConfigPath() string {
	if runtime.GOOS == "windows" {
		user, err := user.Current()
		if err != nil {
			log.Fatal("Error fetching user information: ", err)
		}
		return filepath.Join(user.HomeDir, "Appdata", ".multi-source-downloader", ".config.json")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", ".multi-source-downloader", ".config.json")
}

func saveDownloadConfig(config DownloadConfig) {
	configPath := getDownloadConfigPath()

	// Ensure the directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Fatal("Error creating config directory: ", err)
	}

	// Debugging: Check if the directory was created
	if dirExists(configDir) {
		log.Debugw("Directory created successfully", "directory", configDir)
	} else {
		log.Warnw("Directory not found", "directory", configDir)
	}

	file, err := os.Create(configPath)
	if err != nil {
		log.Fatal("Error creating config file: ", err)
	}
	defer file.Close()

	// Debugging: Check if the file was created
	if _, err := os.Stat(configPath); err == nil {
		log.Debugw("File created successfully", "file", configPath)
	} else {
		log.Warnw("File not found", "file", configPath)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(config); err != nil {
		log.Fatal("Error encoding config JSON: ", err)
	}

	// On Windows, make the file hidden
	if runtime.GOOS == "windows" {
		cmd := fmt.Sprintf("attrib +h %s", configPath)
		if err := exec.Command("cmd", "/C", cmd).Run(); err != nil {
			log.Fatal("Error hiding config file: ", err)
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

func decryptFile(encryptedFilename string, key []byte) error {
	encryptedFile, err := os.Open(encryptedFilename)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	iv := make([]byte, aes.BlockSize)
	_, err = encryptedFile.Read(iv)
	if err != nil {
		return err
	}

	ciphertext, err := io.ReadAll(encryptedFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	paddingLength := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-paddingLength]

	// decryptedFilename := strings.TrimSuffix(encryptedFilename, ".enc") + ".dec"
	decryptedFilename := strings.TrimSuffix(encryptedFilename, ".enc")
	decryptedFile, err := os.Create(decryptedFilename)
	if err != nil {
		return err
	}
	defer decryptedFile.Close()

	_, err = decryptedFile.Write(plaintext)
	if err != nil {
		return err
	}

	log.Debugw("File decrypted successfully and saved as:",
		"decryptedFilename", decryptedFilename,
	)

	return nil
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

func dirExists(path string) bool {
    stat, err := os.Stat(path)
    if err != nil {
 	   return false
    }
    return stat.IsDir()
} 

func run(maxConcurrentConnections int, hashFileURL string, urlFile string, numParts int){
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

	// Create and initialize the download config
	downloadConfig := DownloadConfig{
		UUID:     uuid.New().String(),
		Filename: fileName,
		URL:      urlFile,
		Etag:	  etag,
		HashType: hashType,
	}

	log.Debugw("Inititalizing download config", "downloadConfig", downloadConfig) // Add debug output

	outFile, err := os.Create(fileName)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	defer outFile.Close()

	partFilesHashes := make([]string, numParts)

	// if maxConcurrentConnections != 0 {
	sem := make(chan struct{}, maxConcurrentConnections) // maxConcurrentConnections is the limit you set
	// }

	for i := 0; i < numParts; i++ {
		if maxConcurrentConnections != 0 {
			sem <- struct{}{} // acquire a token
		}
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

			buf := make([]byte, int64(end-start+1))
			reader := io.LimitReader(resp.Body, int64(end-start+1))
			_, err = io.ReadFull(reader, buf)
			if err != nil {
				log.Fatal("Error: ", err)
			}

			sha256Hash := sha256.Sum256(buf)
			sha256HashString := hex.EncodeToString(sha256Hash[:])

			partFilesHashes[i] = hex.EncodeToString(sha256Hash[:])

			timestamp := time.Now().UnixNano() // UNIX timestamp with nanosecond precision

			log.Debugw(
				"Writing to file: ",
				"sha256 hash file", sha256HashString,
				"timestamp", timestamp,
			) // Print the md5 hash string and the timestamp being written. Debug output

			// Add downloaded part info to the download config
			downloadConfig.DownloadedParts = append(downloadConfig.DownloadedParts, DownloadedPart{
				PartNumber: i + 1,
				FileHash:   sha256HashString,
				Timestamp:  timestamp,
			})

			log.Debugw("Appenging part files metadata in download config", "downloadConfig", downloadConfig) // Add debug output

			outFilePart, err := os.Create(fmt.Sprintf("output-%s-%d.part", sha256HashString, timestamp))
			if err != nil {
				log.Fatal("Error: ", err)
			}
			defer outFilePart.Close()

			_, err = outFilePart.Write(buf)
			if err != nil {
				log.Fatal("Error: ", err)
			}

			log.Debugw(
				"Downloaded part",
				"part file",			i+1,
				"sha256 hash string", 	sha256HashString, 
				"timestamp", 			timestamp,
				"filename", 			outFilePart.Name(),
			) // Print the part being downloaded. Debug output

			if maxConcurrentConnections != 0 {
				<-sem // release the token
			}

		}(i)
	}

	if maxConcurrentConnections != 0 {
		// wait for all tokens to be released
		for i := 0; i < maxConcurrentConnections; i++ {
			sem <- struct{}{}
		}
	}

	wg.Wait()

	// Saving the download config
	saveDownloadConfig(downloadConfig)

	// Obtain the encryption key
	key, err := createEncryptionKey(partFilesHashes)
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	// Encrypt the download config
	configPath := getDownloadConfigPath()
	err = encryptFile(configPath, key)
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	// Decrypt the download config
	err = decryptFile(configPath+".enc", key)
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	// Read the .config.json file
	configFile, err := os.Open(configPath)
	if err != nil {
		log.Fatal("Error opening .config.json: ", err)
	}
	defer configFile.Close()

	// Decode the JSON content into a map
	var config DownloadConfig // The JSON structure defined above as DownloadConfig
	decoder := json.NewDecoder(configFile)
	if err := decoder.Decode(&config); err != nil {
		log.Fatal("Error decoding .config.json: ", err)
	}

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

		// Get the part numbers from the .config.json file
		numI, numJ := -1, -1
		for _, part := range config.DownloadedParts {
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

func execute(cmd *cobra.Command, args []string) {
	if urlFile == "" {
		log.Fatal("Error: the --url flag is required")
	}
	run(maxConcurrentConnections, hashFileURL, urlFile, numParts)
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