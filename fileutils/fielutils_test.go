package fileutils

import (
	"os"
	"testing"

	"github.com/campeon23/split-fetcher/logger"
	"github.com/stretchr/testify/assert"
)

func TestPathExists(t *testing.T) {
	// Setup
	l := logger.InitLogger(true)
	f:= NewFileutils("", "", l)

	// Existing path
	assert.True(t, f.PathExists("."), "Expected '.' to exist")

	// Non-existing path
	assert.False(t, f.PathExists("./nonexistentpath"), "Expected './nonexistentpath' to not exist")
}

func TestCreateFile(t *testing.T) {
	// Setup
	l := logger.InitLogger(true)
	f:= NewFileutils("", "", l)

	// Test creating a new file
	filePath := "./testfile.txt"
	file, err := f.CreateFile(filePath)
	assert.NoError(t, err, "Error creating file")
	assert.NotNil(t, file, "Expected file to not be nil")

	// Cleanup
	file.Close()
	os.Remove(filePath)
}

func TestRemoveExtensions(t *testing.T) {
	l := logger.InitLogger(true)
	f:= NewFileutils("", "", l)

	tests := []struct {
		filename string
		expected string
	}{
		{"test.txt", "test"},
		{"test.tar.gz", "test"},
		{"test", "test"},
	}

	for _, tt := range tests {
		output := f.RemoveExtensions(tt.filename)
		assert.Equal(t, tt.expected, output, "For filename: %s", tt.filename)
	}
}

func TestValidatePath(t *testing.T) {
	l := logger.InitLogger(true)
	f:= NewFileutils("", "", l)

	tests := []struct {
		path     string
		expected string
		hasError bool
	}{
		{"./path/to/dir/", "Valid path. Directory: ./path/to/dir. Filename: ", false},
		{"../path/to/dir", "", true},
		{"/path/to/dir", "", true},
	}

	for _, tt := range tests {
		output, err := f.ValidatePath(tt.path)
		if tt.hasError {
			assert.Error(t, err, "Expected error for path: %s", tt.path)
		} else {
			assert.NoError(t, err, "Expected no error for path: %s", tt.path)
		}

		assert.Equal(t, tt.expected, output, "For path: %s", tt.path)
	}
}
