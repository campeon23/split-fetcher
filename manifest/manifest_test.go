package manifest

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/assert"
)

const (
	// Let's consider an arbitrary upper limit for our validation
	// For example, 01-01-3000 @ 00:00:00 UTC in nanoseconds
	upperLimit int64 = 3250368000000000000
)

const tempFile = "eample.txt"

// isValidEpochNano validates if the provided epoch timestamp in nanoseconds is reasonable.
func isValidEpochNano(epochNano int64) bool {
	return epochNano > 0 && epochNano < upperLimit
}

func setupTest() (*Manifest, *DownloadManifest, string, string) {
	l := logger.InitLogger(true)
	timestamp := 1694268622335882000
	m := NewManifest("", "", int64(timestamp), l)
	
	manifest := DownloadManifest{
		UUID: "sampleUUID",
		Version: "sampleVersion",
		Filename: tempFile,
		FileHash: "samplehash",
		URL: "https://example.com/example.txt",
		Etag: "sampleEtag",
		HashType: "sampleHashType",
		PartsDir: "samplePartsDir",
		PrefixParts: "samplePrefixParts",
		Size: 100,
		NumParts: 10,
		RangeSize: 10,
		DownloadedParts: []DownloadedPart{
			{
				PartNumber: 1,
				FileHash: "sampleFileHash",
				Timestamp: 0,
				PartFile: "samplePartFile",
			},
		},
	}

	fileName := tempFile
	hash := md5.Sum([]byte("samplehash"))

	return m, &manifest, fileName, hex.EncodeToString(hash[:])
}

func splitPath(filename string) (string, string, string, string, string, error) {
	extension := filepath.Ext(filename)
	filenameBase := filepath.Base(filename)
	parts := strings.Split(filename[:len(filenameBase)-len(extension)] , "-")
	if len(parts) != 4 {
		// Handle the error or unexpected input accordingly
		return "", "", "", "", "", fmt.Errorf("invalid input")
	}
	return parts[0], parts[1], parts[2], parts[3], extension, nil
}

func TestManifestPath(t *testing.T) {
	assert := assert.New(t)

	l := logger.InitLogger(true)
	m := NewManifest("", "", 0, l)

	fileName := tempFile
	hash := "samplehash"
	path, err := m.ManifestPath(fileName, hash)

	// With assert, the checks become more concise and readable
	assert.Nil(err, "Error getting manifest path")
	assert.True(filepath.IsAbs(path), "Returned path is not absolute")
	assert.Equal(".json", filepath.Ext(path), "Manifest file should have .json extension")
}

func TestSaveDownloadManifest(t *testing.T) {
	assert := assert.New(t)
	m, manifest, fileName, hash := setupTest()

	_, err := m.DownloadManifestObject(*manifest, fileName, hash)
	assert.Nil(err, "Error saving download manifest")
}

func TestEncodeDownloadManifestToJSON(t *testing.T) {
	assert := assert.New(t)
	m, manifest, fileName, hash := setupTest()

	contentData, _ := m.DownloadManifestObject(*manifest, fileName, hash)
	_, err := json.Marshal(contentData)
	assert.NoError(err, "error encoding manifest JSON")
}

func TestManifestFileCreation(t *testing.T) {
	assert := assert.New(t)
	m, _, filename, hash := setupTest()
	hashRegex := regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

	path, _ := m.ManifestPath(filename, hash)
	_, err := os.Stat(path)
	assert.True(os.IsNotExist(err), "Manifest file not created")

	filenameBase := filepath.Base(path)

	name, typeFile, hash, timestampStr, extension, err := splitPath(filenameBase)
	assert.NoError(err, "Error splitting path")
	nameValue := interface{}(name)
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	assert.NoError(err, "Error converting timestamp to int64")
	assert.NoError(err, "Error splitting path")
	_, ok := nameValue.(string)
	// Assert that the name is a string
	assert.True(ok, "Name is not a string")
	// Assert that the file type is "manifest"
	assert.Equal("manifest", typeFile)
	// Assert that the hash is a valid MD5 hash
	assert.True(hashRegex.MatchString(hash))
	// Assert that the timestamp is valid
	assert.True(isValidEpochNano(timestamp))
	assert.NoError(err, "Error parsing timestamp")
	// Assert that the extension is ".json"
	assert.Equal(".json", extension)
}

func TestReadAndDecodeManifestFile(t *testing.T) {
	assert := assert.New(t)
	var decodeData DownloadManifest
	m, manifest, filename, hash := setupTest()


	encodedData, err := json.Marshal(manifest)
	// Assert that there is no error in encoding the manifest
	assert.NoError(err, "Error encoding manifest JSON")
	
	err = json.Unmarshal(encodedData, &decodeData)
	// Assert that there is no error in decoding the manifest
	assert.NoError(err, "error decoding manifest JSON")

	contentData, err := m.DownloadManifestObject(*manifest, filename, hash)
	assert.NoError(err, "Error obtaining manifest")
	err = json.Unmarshal(contentData, &decodeData)
	// Assert that there is no error in decoding the manifest
	assert.NoError(err, "error decoding manifest JSON")
}

func TestExtractManifestFilePathFileName(t *testing.T) {
	assert := assert.New(t)
	m, manifest, filename, hash := setupTest()

	encodedData, err := m.DownloadManifestObject(*manifest, filename, hash)
	assert.NoError(err, "Error saving download manifest")
	_, _, _, err = m.ExtractManifestFilePathFileName(filename, encodedData)
	assert.NoError(err, "Error extracting manifest file path and file name")
}
