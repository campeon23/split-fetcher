package encryption

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/assert"
)

func TestCreateEncryptionKey(t *testing.T) {
	partsDir := "test_data_tmp"
	prefixParts := "part_"

	e := NewEncryption("", "", nil) // Adjust as needed
	l := logger.InitLogger(true)

	currentDir, err := os.Getwd()
	assert.NoErrorf(t, err, "Failed to get current dir: %v", err)

	e.PartsDir = currentDir + string(os.PathSeparator) + partsDir
	e.PrefixParts = prefixParts

	err = os.Mkdir(partsDir, 0755)
	assert.NoErrorf(t, err, "Failed to create test directory: %v", err)
	defer os.RemoveAll(partsDir) // Cleanup

	// Create temp files
	strings := []string{"test1", "test2", "test3"}
	for _, s := range strings {
		tempFile, err := os.CreateTemp(partsDir,  prefixParts + s +"*")
		assert.NoErrorf(t, err, "Failed to create temp file: %v", err)
		_, err = tempFile.WriteString(fmt.Sprintf("Content for %s", s))
		assert.NoErrorf(t, err, "Failed to write to temp file: %v", err)
		tempFile.Close()
	}

	key, err := e.CreateEncryptionKey(strings)

	l.Debugf("key: %v", key)

	assert.NoErrorf(t, err, "Failed to create encryption key: %v", err)
	assert.NotNil(t, key)
	assert.Equal(t, 32, len(key))
}

func TestEncryptFileAndDecryptFile(t *testing.T) {
	partsDir := "test_data_tmp"

	l := logger.InitLogger(true)
	e := NewEncryption("", "", l) // Adjust as needed
	

	currentDir, err := os.Getwd()
	assert.NoErrorf(t, err, "Failed to get current dir: %v", err)

	e.PartsDir = currentDir + string(os.PathSeparator) + partsDir

	err = os.Mkdir(partsDir, 0755)
	assert.NoErrorf(t, err, "Failed to create test directory: %v", err)
	defer os.RemoveAll(partsDir) // Cleanup

	testString := "This is a test string."
	filename := "test.txt"
	encryptedFilename := filename + ".enc"
	decryptedFilename := "test.txt"

	// Create a test file
	err = os.WriteFile(path.Join(e.PartsDir, filename), []byte(testString), 0644)
	assert.NoErrorf(t, err, "Failed to create test file: %v", err)

	// Mocked key for encryption (32 bytes for this example)
	mockKey := []byte("abcdefghijklmnopqrstuvwxyzabcdef") // Change this to the desired key value

	assert.NoErrorf(t, err, "Failed to create encryption key: %v", err)

	// Encrypt the test file
	err = e.EncryptFile(path.Join(e.PartsDir, filename), mockKey)
	assert.NoErrorf(t, err, "Failed to encrypt file: %v", err)
	os.Remove(path.Join(e.PartsDir, filename))

	// Decrypt the file to memory
	decryptedBytes, err := e.DecryptFile(path.Join(e.PartsDir, encryptedFilename), mockKey, false)
	assert.NoErrorf(t, err, "Failed to decrypt file: %v", err)
	assert.Equal(t, testString, string(decryptedBytes))

	// Decrypt the file to disk
	_, err = e.DecryptFile(path.Join(e.PartsDir, encryptedFilename), mockKey, true)
	assert.NoErrorf(t, err, "Failed to decrypt file: %v", err)

	decryptedContent, err := os.ReadFile(path.Join(e.PartsDir, decryptedFilename))
	assert.NoErrorf(t, err, "Failed to read decrypted file: %v", err)
	assert.Equal(t, testString, string(decryptedContent))
}