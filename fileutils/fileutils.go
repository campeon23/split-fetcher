package fileutils

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
)

type Fileutils struct {
	Log	*logger.Logger
}

func NewFileutils(log *logger.Logger) *Fileutils {
	return &Fileutils{
		Log: log,
	}
}

func (f *Fileutils) PathExists(path string) bool {
    _, err := os.Stat(path)
    return !os.IsNotExist(err)
}

func (f *Fileutils) CreateFile(filePath string) (*os.File, error) {
	// Extract the directory path from the filePath
	dirPath := filepath.Dir(filePath)

	// Extract the file name from the filePath
	fileName := filepath.Base(filePath)

	// Check if the directory exists
	_, err := os.Stat(dirPath)
	if os.IsNotExist(err) {
		// If the directory does not exist, create it
		err = os.MkdirAll(dirPath, 0755)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		// If there is any other error
		return nil, err
	}

	// Reconstruct the complete file path
	filePath = filepath.Join(dirPath, fileName)

    // Initialize the output file
    outFile, err := os.Create(filePath)
    if err != nil {
        f.Log.Fatalw("Error: Failed to create output file", "error", err)
    }

	return outFile, nil
}

func (f *Fileutils) RemoveExtensions(filename string) string {
    parts := strings.Split(filename, ".")
    if len(parts) > 3 {
        // Join back the initial parts, excluding the last two assumed to be extensions
        return strings.Join(parts[:len(parts)-2], ".")
    } else if len(parts) > 1 {
        return parts[0]
    }
    return filename
}

func (f *Fileutils) CombinedMD5HashForPrefixedFiles(dir string, prefix string) (string, error) {
	var hashes []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasPrefix(filepath.Base(path), prefix) {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			hash := md5.Sum(data)
			hashes = append(hashes, hex.EncodeToString(hash[:]))
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	sort.Strings(hashes)

	finalHash := md5.Sum([]byte(strings.Join(hashes, "")))

	return hex.EncodeToString(finalHash[:]), nil
}

func (f *Fileutils) DownloadAndParseHashFile(h *hasher.Hasher, shaSumsURL string) (map[string]string, error) {
	hashes := make(map[string]string)
	if len(shaSumsURL) != 0 {
		f.Log.Infow("Initializing HTTP request")
		f.Log.Debugw("Creating HTTP request for URL", "URL", shaSumsURL)

		var err error
		hashes, err = h.DownloadAndParseHashFile(shaSumsURL)
		if err != nil {
			return nil, err
		}
	}

	return hashes, nil
}

func (f *Fileutils) EnsureAppRoot() (string, error) {
	appRoot, err := os.Getwd()
	if err != nil {
		return "", err
	}

	if !strings.HasSuffix(appRoot, string(os.PathSeparator)) {
		appRoot += string(os.PathSeparator)
	}

	return appRoot, nil
}

func (f *Fileutils) ExtractPathAndFile(input string) (dir, filename string, err error) {
	dir, filename = filepath.Split(input)

    f.Log.Debugw("Extracted path and file",
        "dir", dir,
        "filename", filename,
    )

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return dir, filename, err
		}
	} else if err != nil {
		return dir, filename, err
	}

	return dir, filename, nil
}