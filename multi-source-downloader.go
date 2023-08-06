package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/campeon23/multi-source-downloader/assembler"
	"github.com/campeon23/multi-source-downloader/downloader"
	"github.com/campeon23/multi-source-downloader/encryption"
	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/manifest"
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

func run(maxConcurrentConnections int, shaSumsURL string, urlFile string, numParts int, partsDir string, keepParts bool){
	a := assembler.NewAssembler(partsDir, log)
	d := downloader.NewDownloader(urlFile, numParts, maxConcurrentConnections, partsDir, log)
	e := encryption.NewEncryption(log)
	h := hasher.NewHasher(log)
	m := manifest.NewManifest(log)

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

	downloadManifest, partFilesHashes, size, etag, hashType, rangeSize, fileName := d.DownloadPartFiles()

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
	a.AssembleFileFromParts(downloadManifest, outFile, numParts, rangeSize, size, keepParts, hasher.Hasher{})

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