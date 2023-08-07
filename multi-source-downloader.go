package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
	decryptManifest 			bool
	manifestFile 				string
    downloadOnly 				bool
    assembleOnly 				bool
    outputFile 					string
	verbose 					bool
	log 						*logger.Logger // Declared at package level to use the logger across different functions in this package
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
		manifestFile = viper.GetString("manifest-file")
		decryptManifest = viper.GetBool("decrypt-manifest")
        downloadOnly = viper.GetBool("download-only")
        assembleOnly = viper.GetBool("assemble-only")
        outputFile 	 = viper.GetString("output")
		partsDir 	 = viper.GetString("parts-dir")
		keepParts 	 = viper.GetBool("keep-parts")

		// Process the partsDir value
		processPartsDir()
		// Execute the main function
		execute(cmd, args)
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().IntVarP(&maxConcurrentConnections, "max-connections", "c", 0, `(Optional) Controls how many parts of the 
file are downloaded at the same time. You can set a specific number, 
or if you set it to 0, it will choose the best number for you.`)
	rootCmd.PersistentFlags().StringVarP(&shaSumsURL, 	"sha-sums", 	 "s", "", `(Optional) The URL of the file containing the hashes refers to a file 
with either MD5 or SHA-256 hashes, used to verify the integrity and 
authenticity of the downloaded file.`)
	rootCmd.PersistentFlags().StringVarP(&urlFile, 		"url", 			 "u", "", 	 "(Required) URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&numParts, 		"num-parts", 	 "n", 5, 	 "(Optional) Number of parts to split the download into")
	rootCmd.PersistentFlags().StringVarP(&partsDir, 	"parts-dir", 	 "p", "", 	 "(Optional) The directory to save the parts files")
	rootCmd.PersistentFlags().BoolVarP(&keepParts, 		"keep-parts", 	 "k", false, "(Optional) Whether to keep the parts files after assembly")
	rootCmd.PersistentFlags().BoolVarP(&decryptManifest, "decrypt-manifest", "f", false, "(Optional) If true, decrypts the manifest file")
	rootCmd.PersistentFlags().StringVarP(&manifestFile, "manifest-file", "m", "", 	 "(Required by --assemble-only) Manifest file (must be decrypted) to pass to the main function")
    rootCmd.PersistentFlags().BoolVarP(&downloadOnly, 	"download-only", "d", false, "(Optional) Download part files only if true")
    rootCmd.PersistentFlags().BoolVarP(&assembleOnly, 	"assemble-only", "a", false, "(Optional) Assemble part files only if true and --parts-dir and --manifest flags are passed")
    rootCmd.PersistentFlags().StringVarP(&outputFile, 	"output",		 "o", 		 "output", "(Optional) Name and location of the final output file")
	rootCmd.PersistentFlags().BoolVarP(&verbose,		"verbose", 		 "v", false, `(Optional) Output verbose logging (INFO and Debug), verbose not passed
only output INFO logging.`)

	viper.BindPFlag("max-connections", 	rootCmd.PersistentFlags().Lookup("max-connections"))
	viper.BindPFlag("sha-sums", 		rootCmd.PersistentFlags().Lookup("sha-sums"))
	viper.BindPFlag("url", 				rootCmd.PersistentFlags().Lookup("url"))
	viper.BindPFlag("num-parts", 		rootCmd.PersistentFlags().Lookup("num-parts"))
	viper.BindPFlag("parts-dir", 		rootCmd.PersistentFlags().Lookup("parts-dir"))
	viper.BindPFlag("keep-parts", 		rootCmd.PersistentFlags().Lookup("keep-parts"))
	viper.BindPFlag("decrypt-manifest", rootCmd.PersistentFlags().Lookup("decrypt-manifest"))
	viper.BindPFlag("manifest-file", 	rootCmd.PersistentFlags().Lookup("manifest-file"))
    viper.BindPFlag("download-only", 	rootCmd.PersistentFlags().Lookup("download-only"))
    viper.BindPFlag("assemble-only", 	rootCmd.PersistentFlags().Lookup("assemble-only"))
    viper.BindPFlag("output", 			rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("verbose", 			rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}

func processPartsDir() {
	// If the partsDir is empty, set it to the current directory
	if partsDir != "" {
		var err error
		var currentDir string
		currentDir, err = os.Getwd()
		if err != nil {
			log.Fatal("Failed to get current directory: ", err.Error())
		}
		partsDir = currentDir + string(os.PathSeparator) + partsDir
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

	// Create the directory if it doesn't exist
	if _, err := os.Stat(partsDir); os.IsNotExist(err) {
		err = os.MkdirAll(partsDir, os.ModePerm)
		if err != nil {
			log.Fatal("Failed to create directory: ", err.Error())
		}
	}
}

func run(maxConcurrentConnections int, shaSumsURL string, urlFile string, numParts int, partsDir string, keepParts bool){
	a := assembler.NewAssembler(numParts, partsDir, keepParts, log)
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

	appRoot, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed to get current directory: ", err.Error())
	}

	// If the appRoot doesn't end with a slash, add it 
	if !strings.HasSuffix(appRoot, string(os.PathSeparator)) {
		appRoot += string(os.PathSeparator)
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
	key, err := e.CreateEncryptionKey(partFilesHashes)
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
	a.AssembleFileFromParts(downloadManifest, outFile, size, rangeSize, hasher.Hasher{})

	if !keepParts { // If keepParts is false, remove the part file
		// If partsDir was provided
		log.Debugw("Removing parts directory:",
			"Directory", partsDir,
			"Root directory", appRoot,
		)
		if partsDir != "" && partsDir != "." && partsDir != "./" &&  partsDir != appRoot {
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

	if decryptManifest {
		log.Debugw("Decrypting manifest file", 
			"partsDir", partsDir, 
			"manifestFile", manifestFile,
		)
        if partsDir == "" || manifestFile == "" {
            log.Fatal("Error: --decrypt-manifest requires --parts-dir and --manifest-file")
        }
        
        e := encryption.NewEncryption(log)

		var partFilesHashes []string
		err := filepath.Walk(partsDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Fatal("prevent panic by handling failure accessing a path %q: %v\n", path, err)
			}

			if !info.IsDir() && strings.HasPrefix(info.Name(), "output-") {
				log.Debugw("Part file found", "file", path)
				outputPartFile, err := os.Open(path)
				if err != nil {
					log.Fatal("Error: %v\n", err)
				}
				defer outputPartFile.Close()

				// Calculate the hash from the temporary part file
				h := sha256.New()
				if _, err := io.Copy(h, outputPartFile); err != nil {
					log.Fatal("Error: %v\n", err)
				}
				sha256Hash := h.Sum(nil)
				sha256HashString := hex.EncodeToString(sha256Hash[:])
				partFilesHashes = append(partFilesHashes, sha256HashString)
			}
			return nil
		})
		if err != nil {
			log.Fatal("Error: %v\n", err)
		}
						
		// Obtain the encryption key
		key, err := e.CreateEncryptionKey(partFilesHashes)
		if err != nil {
			log.Fatal("Error:", err)
		}

        // Decrypt the downloaded manifest
        _, err = e.DecryptFile(manifestFile, key, true)
        if err != nil {
            log.Fatal("Decrypting manifest file: ", "error:", err.Error())
        }

    } else if assembleOnly {
		if manifestFile == "" || partsDir == "" {
			log.Fatal("Error: --assemble-only requires --parts-dir and --manifest")
		}
		size := 0
		rangeSize := 0
	
		// Initialize the manifest
		if fileutils.PathExists(manifestFile) {
			// Load file from disk
			manifestContent, err := os.ReadFile(manifestFile)
			if err != nil {
				log.Fatal("Loading manifest file: ", "error", err.Error())
			}

			// Decode the JSON content into a map
			var manifest manifest.DownloadManifest
			err = json.Unmarshal(manifestContent, &manifest)
			if err != nil {
				log.Fatal("Decoding manifest content: ", "error", err.Error())
			}

			// Initialize the output file
			outFile, err := os.Create(outputFile)
			if err != nil {
				log.Fatal("Error: Failed to create output file", "error", err)
			}
			defer outFile.Close()
			
			a := assembler.NewAssembler(numParts, partsDir, keepParts, log)

			a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{}) // make sure to modify this method to receive and handle your manifest file
		} else {
			log.Fatal("Error: manifest file not found")
		}
	} else if downloadOnly {
		if urlFile == "" {
			log.Fatal("Error: --download-only requires --url flag")
		}
		d := downloader.NewDownloader(urlFile, numParts, maxConcurrentConnections, partsDir, log)
		e := encryption.NewEncryption(log)
		m := manifest.NewManifest(log)
        downloadManifest, partFilesHashes, _, _, _, _, fileName := d.DownloadPartFiles()

		// Create the final file we want to assemble
		outFile, err := os.Create(fileName)
		if err != nil {
			log.Fatal("Error: ", err)
		}
		defer outFile.Close()

		// Saving the download manifest
		m.SaveDownloadManifest(downloadManifest)

		// Obtain the encryption key
		key, err := e.CreateEncryptionKey(partFilesHashes)
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

		log.Infow("Part files saved to directory", "directory", partsDir)

	} else {
		if urlFile == "" {
			log.Fatal("Error: the --url flag is required")
		}
		run(maxConcurrentConnections, shaSumsURL, urlFile, numParts, partsDir, keepParts)
	}
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