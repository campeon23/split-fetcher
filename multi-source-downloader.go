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
	prefixParts 				string
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
		prefixParts	 = viper.GetString("prefix-parts")
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
	rootCmd.PersistentFlags().StringVarP(&urlFile, 		"url", 			 "u", "",			"(Required) URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&numParts, 		"num-parts", 	 "n", 2, 	 		"(Optional) Number of parts to split the download into")
	rootCmd.PersistentFlags().StringVarP(&partsDir, 	"parts-dir", 	 "p", "", 	 		"(Optional) The directory to save the parts files")
	rootCmd.PersistentFlags().StringVarP(&prefixParts, 	"prefix-parts",  "x", "output-", 	"(Optional) The prefix to use for naming the parts files")
	rootCmd.PersistentFlags().BoolVarP(&keepParts, 		"keep-parts", 	 "k", false, 		"(Optional) Whether to keep the parts files after assembly")
	rootCmd.PersistentFlags().BoolVarP(&decryptManifest, "decrypt-manifest", "f", false, 	"(Optional) If true, decrypts the manifest file")
	rootCmd.PersistentFlags().StringVarP(&manifestFile, "manifest-file", "m", "", 	 		"(Required by --assemble-only) Manifest file (must be decrypted) to pass to the main function")
    rootCmd.PersistentFlags().BoolVarP(&downloadOnly, 	"download-only", "d", false, 		"(Optional) Download part files only if true")
    rootCmd.PersistentFlags().BoolVarP(&assembleOnly, 	"assemble-only", "a", false, 		"(Optional) Assemble part files only if true and --parts-dir and --manifest flags are passed")
    rootCmd.PersistentFlags().StringVarP(&outputFile, 	"output",		 "o", "", 			"(Optional) Name and location of the final output file")
	rootCmd.PersistentFlags().BoolVarP(&verbose,		"verbose", 		 "v", false, 		`(Optional) Output verbose logging (INFO and Debug), verbose not passed
only output INFO logging.`)

	viper.BindPFlag("max-connections", 	rootCmd.PersistentFlags().Lookup("max-connections"))
	viper.BindPFlag("sha-sums", 		rootCmd.PersistentFlags().Lookup("sha-sums"))
	viper.BindPFlag("url", 				rootCmd.PersistentFlags().Lookup("url"))
	viper.BindPFlag("num-parts", 		rootCmd.PersistentFlags().Lookup("num-parts"))
	viper.BindPFlag("parts-dir", 		rootCmd.PersistentFlags().Lookup("parts-dir"))
	viper.BindPFlag("prefix-parts", 	rootCmd.PersistentFlags().Lookup("prefix-parts"))
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
			log.Fatalw("Failed to get current directory: ", "error", err.Error())
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
			log.Fatalf("Failed to create directory: %v", err)
		}
	}
}

func run(maxConcurrentConnections int, shaSumsURL string, urlFile string, numParts int, partsDir string, keepParts bool, prefixParts string, outputFile string){
	a := assembler.NewAssembler(numParts, partsDir, keepParts, prefixParts, log)
	d := downloader.NewDownloader(urlFile, numParts, maxConcurrentConnections, partsDir, prefixParts, log)
	e := encryption.NewEncryption(log)
	f := fileutils.NewFileutils(log)
	h := hasher.NewHasher(log)

	appRoot, _ := f.EnsureAppRoot()

	downloadManifest, hashes, manifestPath, key, size, rangeSize, fileName, _, etag, hashType, err := d.Download(shaSumsURL, partsDir, prefixParts, urlFile, downloadOnly, outputFile)
	if err != nil {
		log.Fatalw("Error: ", err)
	}

	originalFileName := fileName

	outFile, err := f.CreateFile(fileName)
	if err != nil {
		log.Fatalw("Found path in string. Faied to create file.", "error", err.Error())
	}
	defer outFile.Close()

	// Decrypt the downloaded manifest
	var decryptedContent []byte
	decryptedContent, err = e.DecryptFile(manifestPath + ".enc", key, false)
	if err != nil {
		log.Fatalw("Decrypting manifest file: ", "error:", err.Error())
		return
	}

	// Decode the JSON content into a map
	var manifest manifest.DownloadManifest // The JSON structure defined above as DownloadManifest
	err = json.Unmarshal(decryptedContent, &manifest)
	if err != nil {
		log.Fatalw("Decoding decrypted content: ", "error", err.Error())
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
				log.Fatalw("Failed to remove directory: ", "error", err.Error())
			}
		}
	}

	hash, ok := hashes[originalFileName] // This should be in the same method or function as your switch statement.

	h.ValidateFileIntegrity(fileName, originalFileName, hashType, etag, hash, ok)
}

func execute(cmd *cobra.Command, args []string) {
	log = logger.InitLogger(verbose) // Keep track of returned logger
    log.Debugw("Logger initialized")

	d := downloader.NewDownloader(urlFile, numParts, maxConcurrentConnections, partsDir, prefixParts, log)
	f := fileutils.NewFileutils(log)
	h := hasher.NewHasher(log)

	if decryptManifest {
		log.Debugw("Decrypting manifest file", 
			"partsDir", partsDir, 
			"manifestFile", manifestFile,
		)
        if partsDir == "" || manifestFile == "" {
            log.Fatalw("Error: --decrypt-manifest requires --parts-dir and --manifest-file")
        }
        
        e := encryption.NewEncryption(log)

		// Search for all $prefixParts* files in the current directory
		var partFilesHashes []string
		err := filepath.Walk(partsDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Fatalf("Prevent panic by handling failure accessing a path %q: %v\n", path, err)
			}

			if !info.IsDir() && strings.HasPrefix(info.Name(), prefixParts) {
				log.Debugw("Part file found", "file", path)
				// Open the temporary part file
				outputPartFile, err := os.Open(path)
				if err != nil {
					log.Fatalf("Failed to open the temporary part file: %v\n", err)
				}
				defer outputPartFile.Close()

				// Calculate the hash from the temporary part file
				h := sha256.New()
				if _, err := io.Copy(h, outputPartFile); err != nil {
					log.Fatalf("Failed to calculate the hash from the temporary part file: %v\n", err)
				}
				sha256Hash := h.Sum(nil)
				sha256HashString := hex.EncodeToString(sha256Hash[:])
				partFilesHashes = append(partFilesHashes, sha256HashString)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("Failed to search for files in the current directory: %v\n", err)
		}
						
		// Obtain the encryption key
		key, err := e.CreateEncryptionKey(partFilesHashes)
		if err != nil {
			log.Fatalw("Error:", err)
		}

        // Decrypt the downloaded manifest
        _, err = e.DecryptFile(manifestFile, key, true)
        if err != nil {
            log.Fatalw("Decrypting manifest file: ", "error:", err.Error())
        }

    } else if assembleOnly {
		if manifestFile == "" || partsDir == "" {
			log.Fatalw("Error: --assemble-only requires --parts-dir and --manifest")
		}
		size := 0
		rangeSize := 0
	
		// Initialize the manifest
		if f.PathExists(manifestFile) {
			// Load file from disk
			manifestContent, err := os.ReadFile(manifestFile)
			if err != nil {
				log.Fatalw("Loading manifest file: ", "error", err.Error())
			}

			// Decode the JSON content into a map
			var manifest manifest.DownloadManifest
			err = json.Unmarshal(manifestContent, &manifest)
			if err != nil {
				log.Fatalw("Decoding manifest content: ", "error", err.Error())
			}

			if outputFile == "" {
				outputFile = manifest.Filename
			}

			filePath, fileName, err := f.ExtractPathAndFile(outputFile)
			if err != nil {
				log.Fatalf("Could not parse the string:%v", err.Error())
			}

			if fileName == "" {
				outputFile = filepath.Join(filePath, manifest.Filename)
			}

			// Ensure the directory where the output file will be saved exists
			outFile, err := f.CreateFile(outputFile)
			if err != nil {
				log.Fatalw("Error: Found path in string. Faied to create file.", err.Error())
			}
			defer outFile.Close()
			
			a := assembler.NewAssembler(numParts, partsDir, keepParts, prefixParts, log)

			a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{}) // make sure to modify this method to receive and handle your manifest file

			hash := manifest.FileHash
			ok := hash != ""

			// Validate the file integrity
			h.ValidateFileIntegrity(outputFile, manifest.Filename, manifest.HashType, manifest.Etag, hash, ok)

		} else {
			log.Fatalw("Error: manifest file not found")
		}
	} else if downloadOnly {
		d.Download(shaSumsURL, partsDir, prefixParts, urlFile, downloadOnly, outputFile)
	} else {
		if urlFile == "" {
			log.Fatalw("Error: the --url flag is required")
		}
		run(maxConcurrentConnections, shaSumsURL, urlFile, numParts, partsDir, keepParts, prefixParts, outputFile)
	}
}

func main() {
	// calls the Execute method on the rootCmd object, which is likely an instance of
	// a Cobra command. The Execute method runs the CLI, parsing the command-line 
	// arguments and running the appropriate subcommands or functions as defined in 
	// the program.
	if err := rootCmd.Execute(); err != nil {
		log.Fatalw("Error: ", err)
	}
}