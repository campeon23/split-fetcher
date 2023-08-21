package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/assert"
)

func TestHashFile(t *testing.T) {
	partsDir := "test_data_tmp"
	prefixParts := "testfile"
	data := "Test Data!"

	tests := []struct {
		name           string
		filePath       string
		expectError    bool
		expectedMd5    string
		expectedSha1   string
		expectedSha256 string
	}{
		{
			name:         "valid file",
			filePath:     "./test_data_tmp/sample.txt",
			expectError:  false,
			expectedMd5:  "93cc1170301c1ed21d7fbbe49dc66296",
			expectedSha1: "6d17c1d89fdafee5d697d373bba75ee11fa6682f",
			expectedSha256: "375990365a2852e275370f4c4250b0ae900d78cda4d8195296991616067b8402",
		},
		{
			name:        "invalid file path",
			filePath:    "./test_data_tmp/nonexistent.txt",
			expectError: true,
		},
	}

	if _, err := os.Stat(partsDir); os.IsNotExist(err) {
		// Directory does not exist, so create it
		err := os.Mkdir(partsDir, 0755)
		assert.NoErrorf(t, err, "error creating directory %s", partsDir)
		defer os.RemoveAll(partsDir)
	}

	filePath := filepath.Join(partsDir, "sample.txt")
	err := os.WriteFile(filePath, []byte(data), 0644)
	assert.NoErrorf(t, err, "error writing file %s", filePath)

	fmt.Printf("Data written to %s successfully!\n", filePath)


	l := logger.InitLogger(true)
	h := NewHasher(partsDir, prefixParts, l)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashes, err := h.HashFile(tt.filePath)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMd5, hashes.Md5)
				assert.Equal(t, tt.expectedSha1, hashes.Sha1)
				assert.Equal(t, tt.expectedSha256, hashes.Sha256)
			}
		})
	}
}

func TestHashesFromFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_data_tmp")
	assert.NoErrorf(t, err, "error creating directory %s", tmpDir)
	defer os.RemoveAll(tmpDir)

	filesContents := []string{"content1", "content2", "content3"}
	prefixParts := "part_"
	for _, content := range filesContents {
		err = os.WriteFile(filepath.Join(tmpDir, prefixParts+content), []byte(content), 0644)
		assert.NoErrorf(t, err, "error writing file %s", content)

	}

	h := &Hasher{}
	hashes, err := h.HashesFromFiles(tmpDir, prefixParts, "sha256")
	assert.NoErrorf(t, err, "error hashing files in directory %s", tmpDir)

	expectedHashes := []string{}
	for _, content := range filesContents {
		hasher := sha256.New()
		hasher.Write([]byte(content))
		expectedHashes = append(expectedHashes, hex.EncodeToString(hasher.Sum(nil)))
	}

	assert.ElementsMatch(t, expectedHashes, hashes)
}
