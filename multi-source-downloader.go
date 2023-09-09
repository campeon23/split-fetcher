package main

import (
	"os"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/campeon23/multi-source-downloader/assembler"
	"github.com/campeon23/multi-source-downloader/config"
	"github.com/campeon23/multi-source-downloader/database/initdb"
	"github.com/campeon23/multi-source-downloader/downloader"
	"github.com/campeon23/multi-source-downloader/encryption"
	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/manifest"
	"github.com/campeon23/multi-source-downloader/pprofutils"
	"github.com/campeon23/multi-source-downloader/utils"
)

var errCh = make(chan error, 2)
var configOnce sync.Once
var timestamp int64
var appcfg = &localAppConfig{
    AppConfig: config.NewAppConfig(viper.New()),
	ViperInstance: viper.New(),
}
var dbcfg = &localDBConfig{
    DBConfig: config.NewDBConfig(viper.New()),
	ViperInstance: viper.New(),
}
var ppcfg = &localPprofConfig{
    PprofConfig: config.NewPprofConfig(viper.New()),
	ViperInstance: viper.New(),
}
var flags = &localFlags{
    Flags: config.NewFlags(),
}

type localAppConfig struct {
    *config.AppConfig
	ViperInstance *viper.Viper
}
type localPprofConfig struct {
    *config.PprofConfig
	ViperInstance *viper.Viper
}
type localDBConfig struct {
    *config.DBConfig
	ViperInstance *viper.Viper
}
type localFlags struct {
    *config.Flags
}

var rootCmd = &cobra.Command{
	Use:   "multi-source-downloader",
	Short: `The downloader is a Go app that fetches files in parts concurrently, 
with options for integrity validation and connection limits.`,
	Long:  `The multiple source downloader is an application written in Go that splits the file 
to be downloaded into n parts and downloads them concurrently in an optimized manner. 
It then assembles the final file, with support for either Etag validation or Hash 
validation, to ensure file integrity. And more things...`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Logger
		appcfg.Log = logger.InitLogger(appcfg.Verbose)
		dbcfg.Log = logger.InitLogger(appcfg.Verbose)
		ppcfg.Log = logger.InitLogger(appcfg.Verbose)
		appcfg.Log.Debugw("Logger initialized")

		// Execute the pprof server
		if ppcfg.EnablePprof {
			if os.Getenv("ENV_MODE") == "development" {
				ppcfg.Execute(cmd, args)
			} else {
				ppcfg.Log.Debugw("Pprof server not started. ENV_MODE not in development mode.")
			}
		}

		// Execute the db function
		dbcfg.Execute(cmd, args)

		// Execute the main function
		appcfg.Execute(cmd, args)

		// Dump debug information
		if ppcfg.EnablePprof {
			if os.Getenv("ENV_MODE") == "development" {
				p := pprofutils.NewPprofUtils(ppcfg.EnablePprof, ppcfg.PprofPort, ppcfg.SecretToken, ppcfg.BaseURL, ppcfg.Log, errCh)
				ppcfg.DumpDebugFinalize(p)
			}
		}
	},
}

func init() {
	// Initializing values from config files
	LoadConfigs()
	// Initialize PprofConfig
	ppcfg.InitConfig(ppcfg.ViperInstance) // Initializes pprof server configuration

	// Initialize AppConfig 
	appcfg.InitConfig(appcfg.ViperInstance) // Initializes app configuration

	// Initialize DBConfig 
	dbcfg.InitConfig(dbcfg.ViperInstance) // Initializes db configuration

	// Initializing values from flags values
	cobra.OnInitialize(func() {
		ppcfg.InitConfig(ppcfg.ViperInstance)
	})
	cobra.OnInitialize(func() {
		appcfg.InitConfig(appcfg.ViperInstance)
	})
	cobra.OnInitialize(func() {
		dbcfg.InitConfig(dbcfg.ViperInstance)
	})
	// Initialize the Flags struct
	rootCmd.PersistentFlags().IntVarP(&appcfg.MaxConcurrentConnections, flags.MaxConcurrentConnections, "c", 0, `(Optional) Controls how many parts of the file are downloaded at the same time. 
You can set a specific number, or if you set it to 0, it will choose the maximum 
concurrent connections, equal to the number of chunk parts to split the file.`)
	rootCmd.PersistentFlags().StringVarP(&appcfg.ShaSumsURL, 	flags.ShaSumsURL, 	 	"s", "", 		`(Optional) The URL of the file containing the hashes refers to a file with either MD5 or 
SHA-256 hashes, used to verify the integrity and  authenticity of the downloaded file.`)
	rootCmd.PersistentFlags().StringVarP(&appcfg.UrlFile, 		flags.UrlFile, 			"u", "",		"(Required) URL of the file to download")
	rootCmd.PersistentFlags().IntVarP(&appcfg.NumParts, 		flags.NumParts, 	 	"n", 2, 	 	"(Optional) Number of parts to split the download into. Default value is 2")
	rootCmd.PersistentFlags().StringVarP(&appcfg.PartsDir, 		flags.PartsDir, 	  	"p", "", 	 	"(Optional) The directory to save the parts files")
	rootCmd.PersistentFlags().StringVarP(&appcfg.PrefixParts, 	flags.PrefixParts, 	 	"x", "output",	"(Optional) The prefix to use for naming the parts files")
	rootCmd.PersistentFlags().StringVarP(&appcfg.Proxy, 		flags.Proxy, 		 	"r", "", 	 	"(Optional) Proxy to use for the download")
	rootCmd.PersistentFlags().BoolVarP(&appcfg.KeepParts, 		flags.KeepParts, 	 	"k", false, 	"(Optional) Whether to keep the parts files after assembly")
	rootCmd.PersistentFlags().BoolVarP(&appcfg.DecryptManifest,flags.DecryptManifest,	"f", false, 	"(Optional) If true, decrypt the manifest file")
	rootCmd.PersistentFlags().StringVarP(&appcfg.ManifestFile, flags.ManifestFile,		"m", "", 	 	"(Required by --assemble-only) Manifest file (must be decrypted) to pass to the main function")
    rootCmd.PersistentFlags().BoolVarP(&appcfg.DownloadOnly, 	flags.DownloadOnly, 	"d", false, 	"(Optional) Download part files only if true")
    rootCmd.PersistentFlags().BoolVarP(&appcfg.AssembleOnly, 	flags.AssembleOnly, 	"a", false, 	"(Optional) Assemble part files only if true and --parts-dir and --manifest flags are passed")
    rootCmd.PersistentFlags().StringVarP(&appcfg.OutputFile, 	flags.OutputFile,		"o", "", 		"(Optional) Name and location of the final output file")
	rootCmd.PersistentFlags().BoolVarP(&appcfg.Verbose,			flags.Verbose, 		 	"v", false, 	`(Optional) Output verbose logging (INFO and Debug), verbose not passed
only output INFO logging.`)
	rootCmd.PersistentFlags().BoolVarP(&ppcfg.EnablePprof, 	flags.EnablePprof,  	"e", false, 	"Enable pprof profiling. This parameter will only work, if a pprof configuration file exits.")
	appcfg.BindFlagToViper(flags.MaxConcurrentConnections, appcfg.Log)
	appcfg.BindFlagToViper(flags.ShaSumsURL, appcfg.Log)
	appcfg.BindFlagToViper(flags.UrlFile, appcfg.Log)
	appcfg.BindFlagToViper(flags.NumParts, appcfg.Log)
	appcfg.BindFlagToViper(flags.PartsDir, appcfg.Log)
	appcfg.BindFlagToViper(flags.PartsDir, appcfg.Log)
	appcfg.BindFlagToViper(flags.Proxy, appcfg.Log)
	appcfg.BindFlagToViper(flags.KeepParts, appcfg.Log)
	appcfg.BindFlagToViper(flags.DecryptManifest, appcfg.Log)
	appcfg.BindFlagToViper(flags.ManifestFile, appcfg.Log)
    appcfg.BindFlagToViper(flags.DownloadOnly, appcfg.Log)
    appcfg.BindFlagToViper(flags.AssembleOnly, appcfg.Log)
    appcfg.BindFlagToViper(flags.OutputFile, appcfg.Log)
	appcfg.BindFlagToViper(flags.Verbose, appcfg.Log)
	ppcfg.BindFlagToViper(flags.EnablePprof, ppcfg.Log)
}

func (appcfg *localAppConfig) BindFlagToViper(flagName string, log logger.LoggerInterface) {
	err := viper.BindPFlag(flagName, rootCmd.PersistentFlags().Lookup(flagName))
	if err != nil {
		log.Fatalf("Error binding flag %s to viper for aap config: %v", flagName, err)
	}
}

func (ppcfg *localPprofConfig) BindFlagToViper(flagName string, log logger.LoggerInterface) {
	err := viper.BindPFlag(flagName, rootCmd.PersistentFlags().Lookup(flagName))
	if err != nil {
		log.Fatalf("Error binding flag %s to viper for pprof config: %v", flagName, err)
	}
}

func (dbcfg *localDBConfig) BindFlagToViper(flagName string, log logger.LoggerInterface) {
	err := viper.BindPFlag(flagName, rootCmd.PersistentFlags().Lookup(flagName))
	if err != nil {
		log.Fatalf("Error binding flag %s to viper for db config: %v", flagName, err)
	}
}

func run(appcfg *localAppConfig){

	dbInitializer := &initdb.DBInitImpl{}
	fuInitializer := &fileutils.FileUtilsInitImpl{}
	parameters := downloader.NewParameters(appcfg.UrlFile, appcfg.NumParts, appcfg.MaxConcurrentConnections, appcfg.PartsDir, appcfg.PrefixParts, appcfg.Proxy, timestamp)

	a := assembler.NewAssembler(appcfg.NumParts, appcfg.PartsDir, appcfg.KeepParts, appcfg.PrefixParts, timestamp, appcfg.Log)
	d := downloader.NewDownloader(dbcfg.DBConfig, parameters, appcfg.Log, errCh)
	e := encryption.NewEncryption(dbcfg.DBConfig, dbInitializer, fuInitializer, appcfg.PartsDir, appcfg.PrefixParts, timestamp, appcfg.Log)
	f := fileutils.NewFileutils(appcfg.PartsDir, appcfg.PrefixParts, appcfg.Log)
	h := hasher.NewHasher(appcfg.PartsDir, appcfg.PrefixParts, appcfg.Log)
	u := utils.NewUtils(appcfg.PartsDir, appcfg.Log)

	appRoot, err := f.EnsureAppRoot()
	if err != nil {
		appcfg.Log.Fatalf("Failed to validate current app root: %w", err)
	}

	_, hashes, manifestPath, key, size, rangeSize, etag, hashType, err := d.Download(appcfg.ShaSumsURL, appcfg.PartsDir, appcfg.PrefixParts, appcfg.UrlFile, appcfg.DownloadOnly, appcfg.OutputFile)
	if err != nil {
		appcfg.Log.Fatalf("Failed to download the part files: %w", err)
	}

	// Decrypt the downloaded manifest
	appcfg.DecryptedContent, err = e.DecryptFile(manifestPath + ".enc", key, false)
	if err != nil {
		appcfg.Log.Fatalf("Decrypting manifest file: %w", err)
	}

	if appcfg.KeepParts {
		// Dump the decrypted content to a JSON file
		err = os.WriteFile(manifestPath, appcfg.DecryptedContent, 0644)
		if err != nil {
			appcfg.Log.Fatalf("Writing decrypted content to JSON file: %w", err)
		}
	}

	manifest, outFile, outputPath, err := a.PrepareAssemblyEnviroment(appcfg.OutputFile, appcfg.DecryptedContent)
	if err != nil {
		appcfg.Log.Fatalf("Failed to prepare assembly environment: %w", err)
	}
	defer outFile.Close() // Close the file after the function returns

	// Clean memory after decoding content
	u.ZeroMemory(appcfg.DecryptedContent)
	appcfg.DecryptedContent = nil

	// Assemble the file from the downloaded parts
	err = a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{})
	if err != nil {
		appcfg.Log.Fatalf("Failed to assemble parts: %w", err)
	}

	err = f.RemovePartsOrDirectory(u, appcfg.KeepParts, appcfg.PartsDir, appRoot, appcfg.PrefixParts)
	if err != nil {
		appcfg.Log.Fatalf("Failed to remove parts or directory: %w", err)
	}

	hash, ok := hashes[manifest.Filename]

	h.ValidateFileIntegrity(outputPath, hashType, etag, hash, ok)
}

func initializeDb(dbcfg *localDBConfig) {
	// Initialize the database
	dbcfg.Log.Debugw("Initializing database")
	i := initdb.NewInitDB(dbcfg.DBDir, dbcfg.DBFilename, dbcfg.Log)

	// Initialize the encrypted database
	db, err := i.InitializeDB(dbcfg.DBPassword)
	if err != nil {
		dbcfg.Log.Fatalf("Failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create or ensure the salt table exists
	if err := i.CreateSaltTable(db); err != nil {
		dbcfg.Log.Fatalf("Failed to create salt table: %w", err)
	}

	if err := i.CreateTimestampIndex(db); err != nil {
		dbcfg.Log.Fatalf("Failed to create timestamp index: %w", err)
	}
}

func (appcfg *localAppConfig) Execute(cmd *cobra.Command, args []string) {
	// Ticket: Logger Initialization Placement 
	// Package Name: main
	// Function Name: execute
	// Description: Logger was initialized inside the execute function.
	// This has been noted and might be considered for a refactor to initialize at the 
	// package or main function level in the future. Doing so would make it available 
	// for all functions and scenarios. Current initialization is scoped to this function.

	// Initialize the timestamp utilize later for functions such as encryption, manifest, etc.
	u := utils.NewUtils(appcfg.PartsDir, appcfg.Log)
	timestamp := u.GenerateTimestamp()

	dbInitializer := &initdb.DBInitImpl{}
	fuInitializer := &fileutils.FileUtilsInitImpl{}
	parameters := downloader.NewParameters(appcfg.UrlFile, appcfg.NumParts, appcfg.MaxConcurrentConnections, appcfg.PartsDir, appcfg.PrefixParts, appcfg.Proxy, timestamp)

	a := assembler.NewAssembler(appcfg.NumParts, appcfg.PartsDir, appcfg.KeepParts, appcfg.PrefixParts, timestamp, appcfg.Log)
	d := downloader.NewDownloader(dbcfg.DBConfig, parameters, appcfg.Log, errCh)
	e := encryption.NewEncryption(dbcfg.DBConfig, dbInitializer, fuInitializer, appcfg.PartsDir, appcfg.PrefixParts, timestamp, appcfg.Log)
	f := fileutils.NewFileutils(appcfg.PartsDir, appcfg.PrefixParts, appcfg.Log)
	h := hasher.NewHasher(appcfg.PartsDir, appcfg.PrefixParts, appcfg.Log)

	manifest.NewManifest(appcfg.PartsDir, appcfg.PrefixParts, timestamp, nil)

	// Process the partsDir value
	err := f.ProcessPartsDir()
	if err != nil {
		appcfg.Log.Fatalf("Failed to create parts directory: %w", err)
	}
	if appcfg.PartsDir == "" {
		appcfg.PartsDir = f.PartsDir
		a.PartsDir = f.PartsDir
		d.Parameters.PartsDir = f.PartsDir
		e.PartsDir = f.PartsDir
	}

	if appcfg.DecryptManifest {
		// Run decrypt manifest process
		runDecryptManifest(e, h, appcfg)
    } else if appcfg.AssembleOnly {
		// Run assemble process
		runAssembleOnly(f, h, a, appcfg)
	} else if appcfg.DownloadOnly {
		_, _, _, _, _, _, _, _, err := d.Download(appcfg.ShaSumsURL, appcfg.PartsDir, appcfg.PrefixParts, appcfg.UrlFile, appcfg.DownloadOnly, appcfg.OutputFile)
		if err != nil {
			appcfg.Log.Fatalf("Failed to download the part files: %w", err)
		}
	} else {
		if appcfg.UrlFile == "" {
			appcfg.Log.Fatalw("Error: the --url flag is required")
		}
		run(appcfg)
	}
}

func (ppcfg *localPprofConfig) Execute(cmd *cobra.Command, args []string) {
	p := pprofutils.NewPprofUtils(ppcfg.EnablePprof, ppcfg.PprofPort, ppcfg.SecretToken, ppcfg.BaseURL, ppcfg.Log, errCh)
	// Conditionally start pprof if the flag is set
    if ppcfg.EnablePprof {
		if os.Getenv("ENV_MODE") == "development" {
			p.StartPprof(ppcfg.CertPath, ppcfg.KeyPath)
		}
    }

	// Listen to errors
	go func() {
		for err := range p.GetErrorChannel() {
			if err != nil {
				ppcfg.Log.Printf("Received an error on pprof error channel: %w", err)
			}
		}
	}()
}

func (dfcg *localDBConfig) Execute(cmd *cobra.Command, args []string) {
	// Initialize the database
	initializeDb(dbcfg)
}


func runDecryptManifest(e *encryption.Encryption, h *hasher.Hasher, appcfg *localAppConfig){
	// Decrypt the downloaded manifest
	appcfg.Log.Debugw("Decrypting manifest file", 
		"partsDir", appcfg.PartsDir, 
		"manifestFile", appcfg.ManifestFile,
	)
	if appcfg.PartsDir == "" || appcfg.ManifestFile == "" {
		appcfg.Log.Fatalw("Error: --decrypt-manifest requires --parts-dir and --manifest-file")
	}

	partFilesHashes, err := h.HashesFromFiles(appcfg.PartsDir, appcfg.PrefixParts, "sha256")
	if err != nil {
		appcfg.Log.Fatalf("Failed to search for files in the current directory: %w", err)
	}
					
	// Obtain the encryption key
	key, err := e.CreateEncryptionKey(appcfg.ManifestFile, partFilesHashes, false)
	if err != nil {
		appcfg.Log.Fatalf("Failed to create encryption key: %w", err)
	}

	// Decrypt the downloaded manifest
	_, err = e.DecryptFile(appcfg.ManifestFile, key, true)
	if err != nil {
		appcfg.Log.Fatalf("Failed to decrypt manifest file: %w", err)
	}
}

func runAssembleOnly(f *fileutils.Fileutils, h *hasher.Hasher, a *assembler.Assembler, appcfg *localAppConfig){
	if appcfg.ManifestFile == "" || appcfg.PartsDir == "" {
			appcfg.Log.Fatalw("Error: --assemble-only requires --parts-dir and --manifest")
		}
		size := 0
		rangeSize := 0
	
		// Initialize the manifest
		if f.PathExists(appcfg.ManifestFile) {
			// Load file from disk
			manifestContent, err := os.ReadFile(appcfg.ManifestFile)
			if err != nil {
				appcfg.Log.Fatalf("Failed to load manifest file: %w", err)
			}

			manifest, outFile, outputPath, err := a.PrepareAssemblyEnviroment(appcfg.OutputFile, manifestContent)
			if err != nil {
				appcfg.Log.Fatalf("Failed to prepare assembly environment: %w", err)
			}
			defer outFile.Close() // Close the file after the function returns

			err = a.AssembleFileFromParts(manifest, outFile, size, rangeSize, hasher.Hasher{}) // make sure to modify this method to receive and handle your manifest file
			if err != nil {
				appcfg.Log.Fatalf("Failed to assemble parts: %w", err)
			}

			hash := manifest.FileHash
			ok := hash != ""

			// Validate the file integrity
			h.ValidateFileIntegrity(outputPath, manifest.HashType, manifest.Etag, hash, ok)
		} else {
			appcfg.Log.Fatalw("Error: manifest file not found")
		}
}

func (ppcfg *localPprofConfig) DumpDebugFinalize(p *pprofutils.PprofUtils) {
	err := p.DumpDebugPProf()
	if err != nil {
		ppcfg.Log.Fatalf("Error starting pprof server: %w", err)
	}
}

func LoadConfigs() {
	configOnce.Do(func() {
		f := fileutils.NewFileutils(appcfg.PartsDir, appcfg.PrefixParts, appcfg.Log)
		viperPpcfg := ppcfg.ViperInstance
		viperAppcfg := appcfg.ViperInstance
		viperDbcfg := dbcfg.ViperInstance

		// Will run only in development mode
		if f.PathExists(ppcfg.ConfigPath) {
			if os.Getenv("ENV_MODE") == "development" {
				if err := f.LoadConfig(viperPpcfg, ppcfg.ConfigName, ppcfg.ConfigPath); err != nil {
					appcfg.Log.Fatalf("Error loading config: %w", err)
				}
				ppcfg.PprofConfig = config.NewPprofConfig(viperPpcfg)
			}
		}

		appcfg.AppConfig = config.NewAppConfig(viperAppcfg)

		if f.PathExists(dbcfg.ConfigPath) {
			if err := f.LoadConfig(viperDbcfg, dbcfg.ConfigName, dbcfg.ConfigPath); err != nil {
				f.Log.Fatalf("Error loading config: %w", err)
			}
			dbcfg.DBConfig = config.NewDBConfig(viperDbcfg)
		}
	})
}

func main() {
	// calls the Execute method on the rootCmd object, which is likely an instance of
	// a Cobra command. The Execute method runs the CLI, parsing the command-line 
	// arguments and running the appropriate subcommands or functions as defined in 
	// the program.
	if err := rootCmd.Execute(); err != nil {
		appcfg.Log.Printf("Error executing rootCmd object from Cobra command: %w", err)
	}
}