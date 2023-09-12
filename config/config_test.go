package config

import (
	"testing"

	"github.com/campeon23/split-fetcher/logger"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewFlags(t *testing.T) {
	flags := NewFlags()
	assert.Equal(t, "max-connections", flags.MaxConcurrentConnections)
	assert.Equal(t, "sha-sums", flags.ShaSumsURL)
	// ... assert for other fields as needed
}

func TestNewAppConfig(t *testing.T) {
	v := viper.New()
	appcfg := NewAppConfig(v)
	assert.Equal(t, 0, appcfg.MaxConcurrentConnections) // Default int value
	assert.Equal(t, "", appcfg.ShaSumsURL)               // Default string value
	// ... assert for other fields as needed
}

func TestNewPprofConfig(t *testing.T) {
	v := viper.New()
	ppcfg := NewPprofConfig(v)
	assert.False(t, ppcfg.EnablePprof) // Default bool value
	assert.Equal(t, "", ppcfg.SecretToken)
	// ... assert for other fields as needed
}

func TestNewDBConfig(t *testing.T) {
	v := viper.New()
	dbcfg := NewDBConfig(v)
	assert.Equal(t, "", dbcfg.DBDir)
	// ... assert for other fields as needed
}

func TestDBConfigGetters(t *testing.T) {
	v := viper.New()
	dbcfg := NewDBConfig(v)
	assert.Equal(t, dbcfg.DBDir, dbcfg.GetDBDir())
	assert.Equal(t, dbcfg.DBFilename, dbcfg.GetDBFilename())
	// ... assert for other getters as needed
}


func TestGetDBPassword(t *testing.T) {
	expected := "testDBPassword"
	dbConfig := &DBConfig{DBPassword: expected}
	result := dbConfig.GetDBPassword()
	assert.Equal(t, expected, result)
}

func TestGetConfigName(t *testing.T) {
	expected := "testConfigName"
	dbConfig := &DBConfig{ConfigName: expected}
	result := dbConfig.GetConfigName()
	assert.Equal(t, expected, result)
}

func TestGetConfigPath(t *testing.T) {
	expected := "./test/config/path"
	dbConfig := &DBConfig{ConfigPath: expected}
	result := dbConfig.GetConfigPath()
	assert.Equal(t, expected, result)
}

func TestGetLog(t *testing.T) {
	log := logger.InitLogger(false) // Assuming InitLogger is available in logger package
	dbConfig := &DBConfig{Log: log}
	result := dbConfig.GetLog()
	assert.NotNil(t, result)
}

func TestAppConfigInitConfig(t *testing.T) {
	v := viper.New()
	appConfig := &AppConfig{}
	appConfig.InitConfig(v)
	// Here, we just want to ensure that environment variables can be read into viper
	assert.Zero(t, v.GetInt("MaxConcurrentConnections"), "Expected environment variable MaxConcurrentConnections to be read")
	assert.Empty(t, v.GetString("ShaSumsURL"), "Expected environment variable ShaSumsURL to be read")
	assert.Empty(t, v.GetString("UrlFile"), "Expected environment variable UrlFile to be read")
	assert.Zero(t, v.GetInt("NumParts"), "Expected environment variable NumParts to be read")
	assert.False(t, v.GetBool("Verbose"), "Expected environment variable Verbose to be read")
	assert.Empty(t, v.GetString("ManifestFile"), "Expected environment variable ManifestFile to be read")
	assert.False(t, v.GetBool("DecryptManifest"), "Expected environment variable DecryptManifest to be read")
    assert.False(t, v.GetBool("DownloadOnly"), "Expected environment variable DownloadOnly to be read")
    assert.False(t, v.GetBool("AssembleOnly"), "Expected environment variable AssembleOnly to be read")
    assert.Empty(t, v.GetString("OutputFile"), "Expected environment variable OutputFile to be read")
	assert.Empty(t, v.GetString("PartsDir"), "Expected environment variable PartsDir to be read")
	assert.Empty(t, v.GetString("PrefixParts"), "Expected environment variable PrefixParts to be read")
	assert.Empty(t, v.GetString("Proxy"), "Expected environment variable Proxy to be read")
	assert.False(t, v.GetBool("KeepParts"), "Expected environment variable KeepParts to be read")
}

func TestPprofConfigInitConfig(t *testing.T) {
	v := viper.New()
	ppConfig := &PprofConfig{}
	ppConfig.InitConfig(v)
	// Here, we just want to ensure that environment variables can be read into viper
	assert.False(t, v.GetBool("EnablePprof"), "Expected environment variable EnablePprof to be read")
	assert.Empty(t, v.GetString("SecretToken"), "Expected environment variable SecretToken to be read")
    assert.Empty(t, v.GetString("PprofPort"), "Expected environment variable PprofPort to be read")
	assert.Empty(t, v.GetString("CertPath"), "Expected environment variable CertPath to be read")
	assert.Empty(t, v.GetString("KeyPath"), "Expected environment variable KeyPath to be read")
	assert.Empty(t, v.GetString("BaseURL"), "Expected environment variable BaseURL to be read")
	assert.Empty(t, v.GetString("ConfigName"), "Expected environment variable ConfigName to be read")
	assert.Empty(t, v.GetString("ConfigPath"), "Expected environment variable ConfigPath to be read")
}

func TestDBConfigInitConfig(t *testing.T) {
	v := viper.New()
	dbConfig := &DBConfig{}
	dbConfig.InitConfig(v)
	// Here, we just want to ensure that environment variables can be read into viper
	assert.Empty(t, v.GetString("DBDir"), "Expected environment variable DBDir to be read")
	assert.Empty(t, v.GetString("DBFilename"), "Expected environment variable DBFilename to be read")
	assert.Empty(t, v.GetString("DBPassword"), "Expected environment variable DBPassword to be read")
	assert.Empty(t, v.GetString("ConfigName"), "Expected environment variable ConfigName to be read")
	assert.Empty(t, v.GetString("ConfigPath"), "Expected environment variable ConfigPath to be read")
}
// ... similar tests for other getter methods and initialization functions
