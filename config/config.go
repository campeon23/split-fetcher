package config

import (
	"database/sql"
	"os"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/spf13/viper"
)

type Flags struct {
	MaxConcurrentConnections	string
	ShaSumsURL 					string
	UrlFile  					string
	NumParts 					string
	PartsDir 					string
	PrefixParts 				string
	Proxy 						string
	KeepParts 					string
	DecryptManifest 			string
	ManifestFile 				string
    DownloadOnly 				string
    AssembleOnly 				string
    OutputFile 					string
	EnablePprof 				string
	Verbose 					string
}

type AppConfig struct {
	EncryptionCurrentVersion 	string
	MaxConcurrentConnections	int
	ShaSumsURL 					string
	UrlFile  					string
	NumParts 					int
	PartsDir 					string
	PrefixParts 				string
	Proxy 						string
	KeepParts 					bool
	DecryptManifest 			bool
	ManifestFile 				string
	ManifestTimestamp 			int64
    DownloadOnly 				bool
    AssembleOnly 				bool
    OutputFile 					string
	Verbose 					bool
	DecryptedContent 			[]byte
	ConfigName					string
	ConfigPath					string
	Log 						logger.LoggerInterface
	BindFlagsToViper 			func(string, logger.LoggerInterface)
}

type PprofConfig struct {
	EnablePprof bool 
	SecretToken	string
	PprofPort 	string
	CertPath	string
	KeyPath		string
	BaseURL		string
	ConfigName	string
	ConfigPath	string
	Log 		logger.LoggerInterface
}

type DBConfig struct {
	DB			*sql.DB
	DBDir		string
	DBFilename	string
	DBPassword	string
	ConfigName 	string
	ConfigPath	string
	Log 		logger.LoggerInterface
}

func NewFlags() *Flags {
	flags := &Flags{
		MaxConcurrentConnections: "max-connections",
		ShaSumsURL 				: "sha-sums",
		UrlFile 				: "url",
		NumParts 				: "num-parts",
		PartsDir 				: "parts-dir",
		PrefixParts 			: "prefix-parts",
		Proxy 					: "proxy",
		KeepParts 				: "keep-parts",
		DecryptManifest 		: "decrypt-manifest",
		ManifestFile 			: "manifest-file",
		DownloadOnly 			: "download-only",
		AssembleOnly 			: "assemble-only",
		OutputFile 				: "output",
		EnablePprof 			: "enable-pprof",
		Verbose 				: "verbose",
	}
	return flags
}

func NewAppConfig(v *viper.Viper) *AppConfig {
	flags := NewFlags()
	appcfg := &AppConfig{
		EncryptionCurrentVersion: v.GetString("ENCRYPTION_CURRENT_VERSION"),
		MaxConcurrentConnections: v.GetInt(flags.MaxConcurrentConnections),
		ShaSumsURL 				: v.GetString(flags.ShaSumsURL),
		UrlFile 				: v.GetString(flags.UrlFile),
		NumParts 				: v.GetInt(flags.NumParts),
		Verbose 				: v.GetBool(flags.Verbose),
		ManifestFile 			: v.GetString(flags.ManifestFile),
		ManifestTimestamp 		: 0,
		DecryptManifest 		: v.GetBool(flags.DecryptManifest),
        DownloadOnly 			: v.GetBool(flags.DownloadOnly),
        AssembleOnly 			: v.GetBool(flags.AssembleOnly),
        OutputFile 	 			: v.GetString(flags.OutputFile),
		PartsDir 	 			: v.GetString(flags.PartsDir),
		PrefixParts	 			: v.GetString(flags.PrefixParts),
		Proxy 		 			: v.GetString(flags.Proxy),
		KeepParts 	 			: v.GetBool(flags.KeepParts),
		ConfigName				: "config",
		ConfigPath				: "./config",
		Log 					: logger.InitLogger(false),
	}
	return appcfg
}

func NewPprofConfig(v *viper.Viper) *PprofConfig {
	flags := NewFlags()
	ppcfg := &PprofConfig{
		EnablePprof	: v.GetBool(flags.EnablePprof),
		SecretToken	: os.Getenv("ENV_PPROF_TOKEN"),
    	PprofPort	: v.GetString("PPROF_PORT"),
		CertPath	: v.GetString("CERT_PATH"),
		KeyPath		: v.GetString("KEY_PATH"),
		BaseURL		: v.GetString("BASE_URL"),
		ConfigName	: "config",
		ConfigPath	: "./pprofutils/config",
		Log			: logger.InitLogger(false),
	}
	return ppcfg
}

func NewDBConfig(v *viper.Viper) *DBConfig {
	dbcfg := &DBConfig{
		DBDir		: v.GetString("DB_DIR"),
		DBFilename	: v.GetString("DB_FILENAME"),
		DBPassword 	: os.Getenv("ENV_DBPASS"),
		ConfigName	: "config",
		ConfigPath	: "./database/config",
		Log 		: logger.InitLogger(false),
	}
	return dbcfg
}

func (dbcfg *DBConfig) GetDB() *sql.DB {
    return dbcfg.DB
}
func (dbcfg *DBConfig) GetDBDir() string {
    return dbcfg.DBDir
}
func (dbcfg *DBConfig) GetDBFilename() string {
    return dbcfg.DBFilename
}
func (dbcfg *DBConfig) GetDBPassword() string {
    return dbcfg.DBPassword
}
func (dbcfg *DBConfig) GetConfigName() string {
    return dbcfg.ConfigName
}
func (dbcfg *DBConfig) GetConfigPath() string {
    return dbcfg.ConfigPath
}

func (dbcfg *DBConfig) GetLog() logger.LoggerInterface {
    return dbcfg.Log
}

func (appcfg *AppConfig) InitConfig(v *viper.Viper) {
	v.AutomaticEnv() // read in environment variables that match
}

func (ppcfg *PprofConfig) InitConfig(v *viper.Viper) {
	v.AutomaticEnv() // read in environment variables that match
}

func (dbcfg *DBConfig) InitConfig(v *viper.Viper) {
	v.AutomaticEnv() // read in environment variables that match
}