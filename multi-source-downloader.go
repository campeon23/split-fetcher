package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/campeon23/multi-source-downloader/assembler"
	"github.com/campeon23/multi-source-downloader/downloader"
	"github.com/campeon23/multi-source-downloader/encryption"
	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/pprofutils"
	"github.com/campeon23/multi-source-downloader/utils"
)

const ( 
	port = ":6060"
)

var (
	maxConcurrentConnections 	int
	shaSumsURL 					string
	urlFile  					string
	numParts 					int
	partsDir 					string
	prefixParts 				string
	proxy 						string
	keepParts 					bool
	decryptManifest 			bool
	manifestFile 				string
    downloadOnly 				bool
    assembleOnly 				bool
    outputFile 					string
	verbose 					bool
	log 						*logger.Logger // Declared at package level to use the logger across different functions in this package
	enablePprof 				bool // Uncomment if debuging with pprof
	decryptedContent 			[]byte
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
		manifestFile 	= viper.GetString("manifest-file")
		decryptManifest = viper.GetBool("decrypt-manifest")
        downloadOnly 	= viper.GetBool("download-only")
        assembleOnly 	= viper.GetBool("assemble-only")
        outputFile 	 	= viper.GetString("output")
		partsDir 	 	= viper.GetString("parts-dir")
		prefixParts	 	= viper.GetString("prefix-parts")
		proxy 		 	= viper.GetString("proxy")
		keepParts 	 	= viper.GetBool("keep-parts")
		enablePprof  	= viper.GetBool("enable-pprof") // Uncomment if debuging with pprof

		// Execute the main function
		execute(cmd, args)
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().IntVarP(&maxConcurrentConnections, "max-connections", "c", 0, `(Optional) Controls how many parts of the 
file are downloaded at the same time. You can set a specific number, 
or if you set it to 0, it will choose the maximum concurrenct connections,
equal to the number of chunk parts to split the file.`)
	rootCmd.PersistentFlags().StringVarP(&shaSumsURL, 	"sha-sums", 	 	"s", "", `(Optional) The URL of the file containing the hashes refers to a file 
with either MD5 or SHA-256 hashes, used to verify the integrity and 
authenticity of the downloaded file.`)
	rootCmd.PersistentFlags().StringVarP(&urlFile, 		"url", 			 	 "u", "",		"(Required) URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&numParts, 		"num-parts", 	 	 "n", 2, 	 	"(Optional) Number of parts to split the download into. Default value is 2")
	rootCmd.PersistentFlags().StringVarP(&partsDir, 	"parts-dir", 	  	 "p", "", 	 	"(Optional) The directory to save the parts files")
	rootCmd.PersistentFlags().StringVarP(&prefixParts, 	"prefix-parts", 	 "x", "output", "(Optional) The prefix to use for naming the parts files")
	rootCmd.PersistentFlags().StringVarP(&proxy, 		"proxy", 		 	 "r", "", 	 	"(Optional) Proxy to use for the download")
	rootCmd.PersistentFlags().BoolVarP(&keepParts, 		"keep-parts", 	 	 "k", false, 	"(Optional) Whether to keep the parts files after assembly")
	rootCmd.PersistentFlags().BoolVarP(&decryptManifest, "decrypt-manifest", "f", false, 	"(Optional) If true, decrypts the manifest file")
	rootCmd.PersistentFlags().StringVarP(&manifestFile, "manifest-file", 	 "m", "", 	 	"(Required by --assemble-only) Manifest file (must be decrypted) to pass to the main function")
    rootCmd.PersistentFlags().BoolVarP(&downloadOnly, 	"download-only", 	 "d", false, 	"(Optional) Download part files only if true")
    rootCmd.PersistentFlags().BoolVarP(&assembleOnly, 	"assemble-only", 	 "a", false, 	"(Optional) Assemble part files only if true and --parts-dir and --manifest flags are passed")
    rootCmd.PersistentFlags().StringVarP(&outputFile, 	"output",		 	 "o", "", 		"(Optional) Name and location of the final output file")
	rootCmd.PersistentFlags().BoolVarP(&verbose,		"verbose", 		 	 "v", false, 	`(Optional) Output verbose logging (INFO and Debug), verbose not passed
only output INFO logging.`)
	rootCmd.PersistentFlags().BoolVarP(&enablePprof, 	"enable-pprof",  	 "e", false, 	"Enable pprof profiling") // Uncomment if debuging with pprof

	err := viper.BindPFlag("max-connections", 	rootCmd.PersistentFlags().Lookup("max-connections"))
	if err != nil { log.Fatalf("Error binding flag max-connections to viper: %w", err) }
	err = viper.BindPFlag("sha-sums", 			rootCmd.PersistentFlags().Lookup("sha-sums"))
	if err != nil { log.Fatalf("Error binding flag sha-sums to viper: %w", err) }
	err = viper.BindPFlag("url", 				rootCmd.PersistentFlags().Lookup("url"))
	if err != nil { log.Fatalf("Error binding flag url to viper: %w", err) }
	err = viper.BindPFlag("num-parts", 			rootCmd.PersistentFlags().Lookup("num-parts"))
	if err != nil { log.Fatalf("Error binding flag num-parts to viper: %w", err) }
	err = viper.BindPFlag("parts-dir", 			rootCmd.PersistentFlags().Lookup("parts-dir"))
	if err != nil { log.Fatalf("Error binding flag parts-dir to viper: %w", err) }
	err = viper.BindPFlag("prefix-parts", 		rootCmd.PersistentFlags().Lookup("prefix-parts"))
	if err != nil { log.Fatalf("Error binding flag prefix-parts to viper: %w", err) }
	err = viper.BindPFlag("proxy", 				rootCmd.PersistentFlags().Lookup("proxy"))
	if err != nil { log.Fatalf("Error binding flag proxy to viper: %w", err) }
	err = viper.BindPFlag("keep-parts", 		rootCmd.PersistentFlags().Lookup("keep-parts"))
	if err != nil { log.Fatalf("Error binding flag keep-parts to viper: %w", err) }
	err = viper.BindPFlag("decrypt-manifest", 	rootCmd.PersistentFlags().Lookup("decrypt-manifest"))
	if err != nil { log.Fatalf("Error binding flag decrypt-manifest to viper: %w", err) }
	err = viper.BindPFlag("manifest-file", 		rootCmd.PersistentFlags().Lookup("manifest-file"))
	if err != nil { log.Fatalf("Error binding flag manifest-file to viper: %w", err) }
    err = viper.BindPFlag("download-only", 		rootCmd.PersistentFlags().Lookup("download-only"))
	if err != nil { log.Fatalf("Error binding flag download-only to viper: %w", err) }
    err = viper.BindPFlag("assemble-only", 		rootCmd.PersistentFlags().Lookup("assemble-only"))
	if err != nil { log.Fatalf("Error binding flag assemble-only to viper: %w", err) }
    err = viper.BindPFlag("output", 			rootCmd.PersistentFlags().Lookup("output"))
	if err != nil { log.Fatalf("Error binding flag output to viper: %w", err) }
	err = viper.BindPFlag("verbose", 			rootCmd.PersistentFlags().Lookup("verbose"))
	if err != nil { log.Fatalf("Error binding flag verbose to viper: %w", err) }
	err = viper.BindPFlag("enable-pprof", 		rootCmd.PersistentFlags().Lookup("enable-pprof")) // Uncomment if debuging with pprof
	if err != nil { log.Fatalf("Error binding flag enable-pprof to viper: %w", err) }
}

func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}

func run(maxConcurrentConnections int, shaSumsURL string, urlFile string, numParts int, partsDir string, keepParts bool, prefixParts string, outputFile string){
	a := assembler.NewAssembler(numParts, partsDir, keepParts, prefixParts, log)
	d := downloader.NewDownloader(urlFile, numParts, maxConcurrentConnections, partsDir, prefixParts, proxy, log)
	e := encryption.NewEncryption(partsDir, prefixParts, log)
	f := fileutils.NewFileutils(partsDir, prefixParts, log)
	h := hasher.NewHasher(partsDir, prefixParts, log)
	u := utils.NewUtils(partsDir, log)

	appRoot, _ := f.EnsureAppRoot()

	_, hashes, manifestPath, key, size, rangeSize, etag, hashType, err := d.Download(shaSumsURL, partsDir, prefixParts, urlFile, downloadOnly, outputFile)
	if err != nil {
		log.Fatalf("Failed to download the part files:%w", err)
	}

	// Decrypt the downloaded manifest
	decryptedContent, err = e.DecryptFile(manifestPath + ".enc", key, false)
	if err != nil {
		log.Fatalf("Decrypting manifest file: %w", err)
	}

	if enablePprof {
		// Dump the decrypted content to a JSON file
		err = os.WriteFile(manifestPath, decryptedContent, 0644)
		if err != nil {
			log.Fatalf("Writing decrypted content to JSON file: %w", err)
		}
	}

	manifest, outFile, outputPath, err := a.PrepareAssemblyEnviroment(outputFile, decryptedContent)
	if err != nil {
		log.Fatalf("Failed to prepare assembly environment: %w", err)
	}
	defer outFile.Close() // Close the file after the function returns

	// Clean memory after decoding content
	decryptedContent = nil
	for i := range decryptedContent {
		decryptedContent[i] = 0
	}

	// Assemble the file from the downloaded parts
	err = a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{})
	if err != nil {
		log.Fatalf("Failed to assemble parts: %w", err)
	}

	err = f.RemovePartsOrDirectory(u, keepParts, partsDir, appRoot, prefixParts)
	if err != nil {
		log.Fatalf("Failed to remove parts or directory: %w", err)
	}

	hash, ok := hashes[manifest.Filename] // This should be in the same method or function as the switch statement.

	h.ValidateFileIntegrity(outputPath, hashType, etag, hash, ok)
}

func execute(cmd *cobra.Command, args []string) {
	log = logger.InitLogger(verbose) // Keep track of returned logger
    log.Debugw("Logger initialized")

	a := assembler.NewAssembler(numParts, partsDir, keepParts, prefixParts, log)
	d := downloader.NewDownloader(urlFile, numParts, maxConcurrentConnections, partsDir, prefixParts, proxy, log)
	e := encryption.NewEncryption(partsDir, prefixParts, log)
	f := fileutils.NewFileutils(partsDir, prefixParts, log)
	h := hasher.NewHasher(partsDir, prefixParts, log)
	p := pprofutils.NewPprofUtils(log, port) // Uncomment if debuging with pprof

	// Process the partsDir value
	err := f.ProcessPartsDir()
	if err != nil {
		log.Fatalf("Failed to create parts directory: %w", err)
	}
	if partsDir == "" {
		partsDir = f.PartsDir
		a.PartsDir = f.PartsDir
		d.PartsDir = f.PartsDir
		e.PartsDir = f.PartsDir
	}

	// Conditionally start pprof if the flag is set
    if enablePprof {
		log.Debugw(
			"Starting pprof server...",
			"enablePprof", enablePprof,
		)
        p.StartPprof()
    } // Uncomment if debuging with pprof

	// Listen to errors
	go func() {
		for err := range p.GetErrorChannel() {
			if err != nil {
				log.Fatalf("Received an error on pprof error channel: %w", err)
			}
		}
	}() // Uncomment if debuging with pprof

	if decryptManifest {
		log.Debugw("Decrypting manifest file", 
			"partsDir", partsDir, 
			"manifestFile", manifestFile,
		)
        if partsDir == "" || manifestFile == "" {
            log.Fatalw("Error: --decrypt-manifest requires --parts-dir and --manifest-file")
        }

		partFilesHashes, err := h.HashesFromFiles(partsDir, prefixParts, "sha256")
		if err != nil {
			log.Fatalf("Failed to search for files in the current directory: %w", err)
		}
						
		// Obtain the encryption key
		key, err := e.CreateEncryptionKey(partFilesHashes)
		if err != nil {
			log.Fatalf("Failed to create encryption key: %w", err)
		}

        // Decrypt the downloaded manifest
        _, err = e.DecryptFile(manifestFile, key, true)
        if err != nil {
            log.Fatalf("Failed to decrypt manifest file: %w", err)
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
				log.Fatalf("Failed to load manifest file: %w", err)
			}

			manifest, outFile, outputPath, err := a.PrepareAssemblyEnviroment(outputFile, manifestContent)
			if err != nil {
				log.Fatalf("Failed to prepare assembly environment: %w", err)
			}
			defer outFile.Close() // Close the file after the function returns

			err = a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{}) // make sure to modify this method to receive and handle your manifest file
			if err != nil {
				log.Fatalf("Failed to assemble parts: %w", err)
			}

			hash := manifest.FileHash
			ok := hash != ""

			// Validate the file integrity
			h.ValidateFileIntegrity(outputPath, manifest.HashType, manifest.Etag, hash, ok)
		} else {
			log.Fatalw("Error: manifest file not found")
		}
	} else if downloadOnly {
		_, _, _, _, _, _, _, _, err := d.Download(shaSumsURL, partsDir, prefixParts, urlFile, downloadOnly, outputFile)
		if err != nil {
			log.Fatalf("Failed to download the part files: %w", err)
		}
	} else {
		if urlFile == "" {
			log.Fatalw("Error: the --url flag is required")
		}
		run(maxConcurrentConnections, shaSumsURL, urlFile, numParts, partsDir, keepParts, prefixParts, outputFile)
	}

	if enablePprof {
		err := p.DumpDebugPProf()
		if err != nil {
			log.Fatalf("Error starting pprof server: %w", err)
		}
	} // Uncomment if debuging with pprof
}

func main() {
	// calls the Execute method on the rootCmd object, which is likely an instance of
	// a Cobra command. The Execute method runs the CLI, parsing the command-line 
	// arguments and running the appropriate subcommands or functions as defined in 
	// the program.
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing rootCmd object from Cobra command: %w", err)
	}
}