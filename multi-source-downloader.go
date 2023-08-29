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

var errCh = make(chan error, 2)

type Flags struct {
	maxConcurrentConnections	string
	shaSumsURL 					string
	urlFile  					string
	numParts 					string
	partsDir 					string
	prefixParts 				string
	proxy 						string
	keepParts 					string
	decryptManifest 			string
	manifestFile 				string
    downloadOnly 				string
    assembleOnly 				string
    outputFile 					string
	enablePprof 				string
	verbose 					string
}

type AppConfig struct {
	maxConcurrentConnections	int
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
	decryptedContent 			[]byte
	log 						logger.LoggerInterface
	BindFlagsToViper 			func(string, logger.LoggerInterface)
}

type PprofConfig struct {
	enablePprof 				bool 
	secretToken 				string
	pprofPort 					string
	certPath					string
	keyPath						string
	baseURL						string
	configName					string
	configPath					string
	log 						logger.LoggerInterface
}

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
		ppcfg := NewPprofConfig()  // This will initialize the pprof and other defaults
        ppcfg.InitConfig() // Initializes configuration

		cfg := NewAppConfig()  // This will initialize the logger and other defaults
        cfg.InitConfig() // Initializes configuration

		// Execute the pprof server
		if ppcfg.enablePprof {
			if os.Getenv("ENV_MODE") == "development" {
				ppcfg.Execute(cmd, args)
			} else {
				ppcfg.log.Debugw("Pprof server not started. ENV_MODE not in development mode.")
			}
		}

		// Execute the main function
		cfg.Execute(cmd, args)

		// Dump debug information
		if ppcfg.enablePprof {
			if os.Getenv("ENV_MODE") == "development" {
				p := pprofutils.NewPprofUtils(ppcfg.enablePprof, ppcfg.pprofPort, ppcfg.secretToken, ppcfg.certPath, ppcfg.keyPath, ppcfg.baseURL, ppcfg.log, errCh)
				ppcfg.DumpDebugFinalize(p)
			}
		}
	},
}

func init() {
	cfg := NewAppConfig()
	ppcfg := NewPprofConfig()
	flags := NewFlags()
	f := fileutils.NewFileutils(cfg.partsDir, cfg.prefixParts, cfg.log)
	// Will run only in development mode
	if f.PathExists(ppcfg.configPath) {
		if os.Getenv("ENV_MODE") == "development" {
			err := pprofutils.LoadConfig(ppcfg.configName, ppcfg.configPath)
			if err != nil { cfg.log.Fatalf("Error loading config: %w", err)}
		}
	}

	cobra.OnInitialize(cfg.InitConfig)
	cobra.OnInitialize(ppcfg.InitConfig)
	rootCmd.PersistentFlags().IntVarP(&cfg.maxConcurrentConnections, flags.maxConcurrentConnections, "c", 0, `(Optional) Controls how many parts of the 
file are downloaded at the same time. You can set a specific number, 
or if you set it to 0, it will choose the maximum concurrenct connections,
equal to the number of chunk parts to split the file.`)
	rootCmd.PersistentFlags().StringVarP(&cfg.shaSumsURL, 	flags.shaSumsURL, 	 	"s", "", 		`(Optional) The URL of the file containing the hashes refers to a file 
with either MD5 or SHA-256 hashes, used to verify the integrity and 
authenticity of the downloaded file.`)
	rootCmd.PersistentFlags().StringVarP(&cfg.urlFile, 		flags.urlFile, 			"u", "",		"(Required) URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&cfg.numParts, 		flags.numParts, 	 	"n", 2, 	 	"(Optional) Number of parts to split the download into. Default value is 2")
	rootCmd.PersistentFlags().StringVarP(&cfg.partsDir, 	flags.partsDir, 	  	"p", "", 	 	"(Optional) The directory to save the parts files")
	rootCmd.PersistentFlags().StringVarP(&cfg.prefixParts, 	flags.prefixParts, 	 	"x", "output", "(Optional) The prefix to use for naming the parts files")
	rootCmd.PersistentFlags().StringVarP(&cfg.proxy, 		flags.proxy, 		 	"r", "", 	 	"(Optional) Proxy to use for the download")
	rootCmd.PersistentFlags().BoolVarP(&cfg.keepParts, 		flags.keepParts, 	 	"k", false, 	"(Optional) Whether to keep the parts files after assembly")
	rootCmd.PersistentFlags().BoolVarP(&cfg.decryptManifest,flags.decryptManifest,	"f", false, 	"(Optional) If true, decrypt the manifest file")
	rootCmd.PersistentFlags().StringVarP(&cfg.manifestFile, flags.manifestFile,		"m", "", 	 	"(Required by --assemble-only) Manifest file (must be decrypted) to pass to the main function")
    rootCmd.PersistentFlags().BoolVarP(&cfg.downloadOnly, 	flags.downloadOnly, 	"d", false, 	"(Optional) Download part files only if true")
    rootCmd.PersistentFlags().BoolVarP(&cfg.assembleOnly, 	flags.assembleOnly, 	"a", false, 	"(Optional) Assemble part files only if true and --parts-dir and --manifest flags are passed")
    rootCmd.PersistentFlags().StringVarP(&cfg.outputFile, 	flags.outputFile,		"o", "", 		"(Optional) Name and location of the final output file")
	rootCmd.PersistentFlags().BoolVarP(&cfg.verbose,		flags.verbose, 		 	"v", false, 	`(Optional) Output verbose logging (INFO and Debug), verbose not passed
only output INFO logging.`)
	rootCmd.PersistentFlags().BoolVarP(&ppcfg.enablePprof, 	flags.enablePprof,  	"e", false, 	"Enable pprof profiling. This parameter will only work, if a pprof configuration file exits.")
	cfg.BindFlagToViper(flags.maxConcurrentConnections, cfg.log)
	cfg.BindFlagToViper(flags.shaSumsURL, cfg.log)
	cfg.BindFlagToViper(flags.urlFile, cfg.log)
	cfg.BindFlagToViper(flags.numParts, cfg.log)
	cfg.BindFlagToViper(flags.partsDir, cfg.log)
	cfg.BindFlagToViper(flags.prefixParts, cfg.log)
	cfg.BindFlagToViper(flags.proxy, cfg.log)
	cfg.BindFlagToViper(flags.keepParts, cfg.log)
	cfg.BindFlagToViper(flags.decryptManifest, cfg.log)
	cfg.BindFlagToViper(flags.manifestFile, cfg.log)
    cfg.BindFlagToViper(flags.downloadOnly, cfg.log)
    cfg.BindFlagToViper(flags.assembleOnly, cfg.log)
    cfg.BindFlagToViper(flags.outputFile, cfg.log)
	cfg.BindFlagToViper(flags.verbose, cfg.log)
	ppcfg.BindFlagToViper(flags.enablePprof, ppcfg.log)
}

func (cfg *AppConfig) InitConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}

func (cfg *AppConfig) BindFlagToViper(flagName string, log logger.LoggerInterface) {
	err := viper.BindPFlag(flagName, rootCmd.PersistentFlags().Lookup(flagName))
	if err != nil {
		log.Fatalf("Error binding flag %s to viper: %v", flagName, err)
	}
}

func (ppcfg *PprofConfig) BindFlagToViper(flagName string, log logger.LoggerInterface) {
	err := viper.BindPFlag(flagName, rootCmd.PersistentFlags().Lookup(flagName))
	if err != nil {
		log.Fatalf("Error binding flag %s to viper: %v", flagName, err)
	}
}

func NewFlags() *Flags {
	flags := &Flags{
		maxConcurrentConnections: "max-connections",
		shaSumsURL 				: "sha-sums",
		urlFile 				: "url",
		numParts 				: "num-parts",
		partsDir 				: "parts-dir",
		prefixParts 			: "prefix-parts",
		proxy 					: "proxy",
		keepParts 				: "keep-parts",
		decryptManifest 		: "decrypt-manifest",
		manifestFile 			: "manifest-file",
		downloadOnly 			: "download-only",
		assembleOnly 			: "assemble-only",
		outputFile 				: "output",
		enablePprof 			: "enable-pprof",
		verbose 				: "verbose",
	}
	return flags
}

func NewAppConfig() *AppConfig {
	flags := NewFlags()
	cfg := &AppConfig{
		maxConcurrentConnections: viper.GetInt(flags.maxConcurrentConnections),
		shaSumsURL 				: viper.GetString(flags.shaSumsURL),
		urlFile 				: viper.GetString(flags.urlFile),
		numParts 				: viper.GetInt(flags.numParts),
		verbose 				: viper.GetBool(flags.verbose),
		manifestFile 			: viper.GetString(flags.manifestFile),
		decryptManifest 		: viper.GetBool(flags.decryptManifest),
        downloadOnly 			: viper.GetBool(flags.downloadOnly),
        assembleOnly 			: viper.GetBool(flags.assembleOnly),
        outputFile 	 			: viper.GetString(flags.outputFile),
		partsDir 	 			: viper.GetString(flags.partsDir),
		prefixParts	 			: viper.GetString(flags.prefixParts),
		proxy 		 			: viper.GetString(flags.proxy),
		keepParts 	 			: viper.GetBool(flags.keepParts),
		log 					: logger.InitLogger(viper.GetBool(flags.verbose)),
	}
	return cfg
}

func (ppcfg *PprofConfig) InitConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}

func NewPprofConfig() *PprofConfig {
	flags := NewFlags()
	ppcfg := &PprofConfig{
		enablePprof  			: viper.GetBool(flags.enablePprof),
		secretToken 			: viper.GetString("SECRET_TOKEN"),
    	pprofPort 				: viper.GetString("PPROF_PORT"),
		certPath				: viper.GetString("CERT_PATH"),
		keyPath					: viper.GetString("KEY_PATH"),
		baseURL					: viper.GetString("BASE_URL"),
		configName				: "config",
		configPath				: "./pprofutils/config",
		log 					: logger.InitLogger(viper.GetBool(flags.verbose)),
	}
	return ppcfg
}

func run(cfg *AppConfig){
	a := assembler.NewAssembler(cfg.numParts, cfg.partsDir, cfg.keepParts, cfg.prefixParts, cfg.log)
	d := downloader.NewDownloader(cfg.urlFile, cfg.numParts, cfg.maxConcurrentConnections, cfg.partsDir, cfg.prefixParts, cfg.proxy, cfg.log, errCh)
	e := encryption.NewEncryption(cfg.partsDir, cfg.prefixParts, cfg.log)
	f := fileutils.NewFileutils(cfg.partsDir, cfg.prefixParts, cfg.log)
	h := hasher.NewHasher(cfg.partsDir, cfg.prefixParts, cfg.log)
	u := utils.NewUtils(cfg.partsDir, cfg.log)

	appRoot, err := f.EnsureAppRoot()
	if err != nil {
		cfg.log.Fatalf("Failed to validate current app root: %w", err)
	}

	_, hashes, manifestPath, key, size, rangeSize, etag, hashType, err := d.Download(cfg.shaSumsURL, cfg.partsDir, cfg.prefixParts, cfg.urlFile, cfg.downloadOnly, cfg.outputFile)
	if err != nil {
		cfg.log.Fatalf("Failed to download the part files:%w", err)
	}

	// Decrypt the downloaded manifest
	cfg.decryptedContent, err = e.DecryptFile(manifestPath + ".enc", key, false)
	if err != nil {
		cfg.log.Fatalf("Decrypting manifest file: %w", err)
	}

	if cfg.keepParts {
		// Dump the decrypted content to a JSON file
		err = os.WriteFile(manifestPath, cfg.decryptedContent, 0644)
		if err != nil {
			cfg.log.Fatalf("Writing decrypted content to JSON file: %w", err)
		}
	}

	manifest, outFile, outputPath, err := a.PrepareAssemblyEnviroment(cfg.outputFile, cfg.decryptedContent)
	if err != nil {
		cfg.log.Fatalf("Failed to prepare assembly environment: %w", err)
	}
	defer outFile.Close() // Close the file after the function returns

	// Clean memory after decoding content
	u.ZeroMemory(cfg.decryptedContent)
	cfg.decryptedContent = nil

	// Assemble the file from the downloaded parts
	err = a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{})
	if err != nil {
		cfg.log.Fatalf("Failed to assemble parts: %w", err)
	}

	err = f.RemovePartsOrDirectory(u, cfg.keepParts, cfg.partsDir, appRoot, cfg.prefixParts)
	if err != nil {
		cfg.log.Fatalf("Failed to remove parts or directory: %w", err)
	}

	hash, ok := hashes[manifest.Filename]

	h.ValidateFileIntegrity(outputPath, hashType, etag, hash, ok)
}

func (cfg *AppConfig) Execute(cmd *cobra.Command, args []string) {
	// Ticket: Logger Initialization Placement 
	// Package Name: main
	// Function Name: execute
	// Description: Logger was initialized inside the execute function.
	// This has been noted and might be considered for a refactor to initialize at the 
	// package or main function level in the future. Doing so would make it available 
	// for all functions and scenarios. Current initialization is scoped to this function.
    cfg.log.Debugw("Logger initialized")

	a := assembler.NewAssembler(cfg.numParts, cfg.partsDir, cfg.keepParts, cfg.prefixParts, cfg.log)
	d := downloader.NewDownloader(cfg.urlFile, cfg.numParts, cfg.maxConcurrentConnections, cfg.partsDir, cfg.prefixParts, cfg.proxy, cfg.log, errCh)
	e := encryption.NewEncryption(cfg.partsDir, cfg.prefixParts, cfg.log)
	f := fileutils.NewFileutils(cfg.partsDir, cfg.prefixParts, cfg.log)
	h := hasher.NewHasher(cfg.partsDir, cfg.prefixParts, cfg.log)

	// Process the partsDir value
	err := f.ProcessPartsDir()
	if err != nil {
		cfg.log.Fatalf("Failed to create parts directory: %w", err)
	}
	if cfg.partsDir == "" {
		cfg.partsDir = f.PartsDir
		a.PartsDir = f.PartsDir
		d.PartsDir = f.PartsDir
		e.PartsDir = f.PartsDir
	}

	if cfg.decryptManifest {
		// Run decrypt manifest process
		runDecryptManifest(e, h, cfg)
    } else if cfg.assembleOnly {
		// Run assemble process
		runAssembleOnly(f, h, a, cfg)
	} else if cfg.downloadOnly {
		_, _, _, _, _, _, _, _, err := d.Download(cfg.shaSumsURL, cfg.partsDir, cfg.prefixParts, cfg.urlFile, cfg.downloadOnly, cfg.outputFile)
		if err != nil {
			cfg.log.Fatalf("Failed to download the part files: %w", err)
		}
	} else {
		if cfg.urlFile == "" {
			cfg.log.Fatalw("Error: the --url flag is required")
		}
		run(cfg)
	}
}

func (ppcfg *PprofConfig) Execute(cmd *cobra.Command, args []string) {
	p := pprofutils.NewPprofUtils(ppcfg.enablePprof, ppcfg.pprofPort, ppcfg.secretToken, ppcfg.certPath, ppcfg.keyPath, ppcfg.baseURL, ppcfg.log, errCh)
	// Conditionally start pprof if the flag is set
    if ppcfg.enablePprof {
		if os.Getenv("ENV_MODE") == "development" {
			p.StartPprof()
		}
    }

	// Listen to errors
	go func() {
		for err := range p.GetErrorChannel() {
			if err != nil {
				ppcfg.log.Printf("Received an error on pprof error channel: %w", err)
			}
		}
	}()
}
func runDecryptManifest(e *encryption.Encryption, h *hasher.Hasher, cfg *AppConfig){
	cfg.log.Debugw("Decrypting manifest file", 
		"partsDir", cfg.partsDir, 
		"manifestFile", cfg.manifestFile,
	)
	if cfg.partsDir == "" || cfg.manifestFile == "" {
		cfg.log.Fatalw("Error: --decrypt-manifest requires --parts-dir and --manifest-file")
	}

	partFilesHashes, err := h.HashesFromFiles(cfg.partsDir, cfg.prefixParts, "sha256")
	if err != nil {
		cfg.log.Fatalf("Failed to search for files in the current directory: %w", err)
	}
					
	// Obtain the encryption key
	key, err := e.CreateEncryptionKey(partFilesHashes)
	if err != nil {
		cfg.log.Fatalf("Failed to create encryption key: %w", err)
	}

	// Decrypt the downloaded manifest
	_, err = e.DecryptFile(cfg.manifestFile, key, true)
	if err != nil {
		cfg.log.Fatalf("Failed to decrypt manifest file: %w", err)
	}
}

func runAssembleOnly(f *fileutils.Fileutils, h *hasher.Hasher, a *assembler.Assembler, cfg *AppConfig){
	if cfg.manifestFile == "" || cfg.partsDir == "" {
			cfg.log.Fatalw("Error: --assemble-only requires --parts-dir and --manifest")
		}
		size := 0
		rangeSize := 0
	
		// Initialize the manifest
		if f.PathExists(cfg.manifestFile) {
			// Load file from disk
			manifestContent, err := os.ReadFile(cfg.manifestFile)
			if err != nil {
				cfg.log.Fatalf("Failed to load manifest file: %w", err)
			}

			manifest, outFile, outputPath, err := a.PrepareAssemblyEnviroment(cfg.outputFile, manifestContent)
			if err != nil {
				cfg.log.Fatalf("Failed to prepare assembly environment: %w", err)
			}
			defer outFile.Close() // Close the file after the function returns

			err = a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{}) // make sure to modify this method to receive and handle your manifest file
			if err != nil {
				cfg.log.Fatalf("Failed to assemble parts: %w", err)
			}

			hash := manifest.FileHash
			ok := hash != ""

			// Validate the file integrity
			h.ValidateFileIntegrity(outputPath, manifest.HashType, manifest.Etag, hash, ok)
		} else {
			cfg.log.Fatalw("Error: manifest file not found")
		}
}

func (ppcfg *PprofConfig) DumpDebugFinalize(p *pprofutils.PprofUtils) {
	err := p.DumpDebugPProf()
	if err != nil {
		ppcfg.log.Fatalf("Error starting pprof server: %w", err)
	}
}

func main() {
	// calls the Execute method on the rootCmd object, which is likely an instance of
	// a Cobra command. The Execute method runs the CLI, parsing the command-line 
	// arguments and running the appropriate subcommands or functions as defined in 
	// the program.
	var log = logger.InitLogger(false)
	if err := rootCmd.Execute(); err != nil {
		log.Printf("Error executing rootCmd object from Cobra command: %w", err)
	}
}