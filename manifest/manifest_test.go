package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/assert"
)

func TestGetDownloadManifestPath(t *testing.T) {
	assert := assert.New(t)

	l := logger.InitLogger(true)
	m := NewManifest("", "", l)

	fileName := "example.txt"
	hash := "samplehash"
	path, err := m.GetDownloadManifestPath(fileName, hash)

	// With assert, the checks become more concise and readable
	assert.Nil(err, "Error getting manifest path")
	assert.True(filepath.IsAbs(path), "Returned path is not absolute")
	assert.Equal(".json", filepath.Ext(path), "Manifest file should have .json extension")
}

func TestSaveAndExtractDownloadManifest(t *testing.T) {
	assert := assert.New(t)

	l := logger.InitLogger(true)
	m := NewManifest("", "", l)

	manifest := DownloadManifest{
		UUID: "sampleUUID",
		// ... populate other fields
	}
	fileName := "example.txt"
	hash := "samplehash"

	// Test SaveDownloadManifest
	err := m.SaveDownloadManifest(manifest, fileName, hash)
	assert.Nil(err, "Error saving download manifest")

	// Check if the manifest file is created
	path, _ := m.GetDownloadManifestPath(fileName, hash)
	_, err = os.Stat(path)
	assert.False(os.IsNotExist(err), "Manifest file not created")

	// Test ExtractManifestFilePathFileName
	content, _ := os.ReadFile(path)
	_, _, _, err = m.ExtractManifestFilePathFileName(fileName, content)
	assert.Nil(err, "Error extracting manifest file path and file name")

	// Cleanup: Delete the manifest file
	os.Remove(path)
}

// Add more tests for other methods.
