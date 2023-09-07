package fileutils

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/utils"
	"github.com/spf13/viper"
)

type Fileutils struct {
	PartsDir	string
	PrefixParts	string
	Log			logger.LoggerInterface
}
type FileUtilsInitImpl struct {
    // Any additional fields that you might want to include
}
type FUInitializer interface {
    NewFileutils(partDir string, prefixParts string, log logger.LoggerInterface) FileInterface
}
type FileInterface interface {
    PathExists(path string) bool
    // ... other required methods
}
type FileOperator interface {
    Remove(name string) 	error
    Create(name string) 	(*os.File, error)
	ReadFile(name string)	([]byte, error)
	Open(name string)		(*os.File, error)
	WriteFile(filename string, data []byte, perm os.FileMode) error
    WriteEncryptedFile(filename string, data []byte, key []byte, perm os.FileMode) error
}
type RealFileUtils struct {
	Init *Fileutils
}

func NewFileutils(partsDir string, prefixParts string, log logger.LoggerInterface) *Fileutils {
	return &Fileutils{
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Log: log,
	}
}

func (f *Fileutils) SetLogger(log logger.LoggerInterface) {
    f.Log = log
}

func (fu *FileUtilsInitImpl) NewFileutils(partsDir string, prefixParts string, log logger.LoggerInterface) FileInterface {
    return &RealFileUtils{
        Init: &Fileutils{
            // Necessary fields to initialize your RealDB and its embedded InitDB
			PartsDir: partsDir,
			PrefixParts: prefixParts,
			Log: log,
		},   
    }
}

func (fu *RealFileUtils) PathExists(path string) bool {
	return fu.Init.PathExists(path)
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
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}
	} else if err != nil {
		// If there is any other error
		return nil, fmt.Errorf("failed to validate path: %w", err)
	}

	// Reconstruct the complete file path
	filePath = filepath.Join(dirPath, fileName)

    // Initialize the output file
    outFile, err := os.Create(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to create file: %w", err)
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
	const hashType = "md5"
	h := hasher.NewHasher(f.PartsDir, f.PrefixParts, f.Log)

	hashes, err := h.HashesFromFiles(dir, prefix, hashType)
	if err != nil {
		return "", fmt.Errorf("failed to search for files in the current directory: %v", err)
	}

	sort.Strings(hashes)

	finalHash := md5.Sum([]byte(strings.Join(hashes, "")))

	return hex.EncodeToString(finalHash[:]), nil
}

func (f *Fileutils) EnsureAppRoot() (string, error) {
	appRoot, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to obtain the current working directory: %v", err)
	}

	if !strings.HasSuffix(appRoot, string(os.PathSeparator)) {
		appRoot += string(os.PathSeparator)
	}

	return appRoot, nil
}

func (f *Fileutils) ValidateCreatePath(path string) (error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to validate path: %w", err)
	}
	return nil
}

// ExtractDirFilename extracts the directory and filename from a given path.
func (f *Fileutils) ExtractPathAndFilename(path string) (string, string, error) {
	parts := strings.Split(path, "/")

	directory := ""
	filename := ""

	// If path ends with '/', it's a directory
	if strings.HasSuffix(path, "/") {
		directory = strings.Join(parts[:len(parts)-1], "/")
	} else {
		if len(parts) > 1 {
			directory = strings.Join(parts[:len(parts)-1], "/")
			filename = parts[len(parts)-1]
		} else {
			filename = parts[0]
		}
	}
	f.Log.Debugw(
		"Extracting directory and filename from path", 
		"path", path,
		"parts", parts,
		"filename", filename,
		"directory", directory,
	)
	
	return directory, filename, nil
}

// ValidatePath checks if the given path adheres to our constraints.
func (f *Fileutils) ValidatePath(path string) (string, error) {
	currentDirectory, err := os.Getwd()
    if err != nil {
        return "", errors.New("error getting current directory")
    }

    homeDir, err := os.UserHomeDir()
    if err != nil {
        return "", errors.New("error getting user home directory")
    }

    // Check for path escaping out of home directory
    if strings.Contains(path, "../") {
        return "", errors.New("invalid path - escaping directory not allowed")
    }

    // Check if the path is absolute (starts with "/")
    if strings.HasPrefix(path, "/") {
        if !strings.HasPrefix(path, currentDirectory) && !strings.HasPrefix(path, homeDir) {
            return "", errors.New("invalid path - outside home or app directory not allowed")
        }
    }

    // Regular expression for valid directory and path names
    dirRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
    filenameRegex := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

    // Split path and validate each part
    parts := strings.Split(path, "/")
	// splitValidatePath splits the path and validates each part
	err = f.splitValidatePath(parts, dirRegex, filenameRegex)
	if err != nil {
		return "", fmt.Errorf("failed to split and to validate path: %w", err)
	}

    // Check for valid paths starting with ~ or ./
    if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "~/") {
        directory, filename, err := f.ExtractPathAndFilename(path)
        if err != nil {
            return "", errors.New("invalid path format")
        }
        return fmt.Sprintf("Valid path. Directory: %s. Filename: %s", directory, filename), nil
    }

	return fmt.Sprintf("Valid path. Directory: %s", path), nil
}

func (f *Fileutils) splitValidatePath(parts []string, dirRegex *regexp.Regexp, filenameRegex *regexp.Regexp) error{
	for _, part := range parts {
        if part == "." || part == "~" || part == "" {
            continue
        }
        if !dirRegex.MatchString(part) && !filenameRegex.MatchString(part) {
            return errors.New("invalid character in path or filename")
        }
    }
	return nil
}

func (f *Fileutils) ProcessPartsDir() error {
	if f.PartsDir == "" {
		var err error
		f.PartsDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("error getting current directory: %w", err)
		}
	}

	_, err := f.ValidatePath(f.PartsDir)
	if err != nil {
		return fmt.Errorf("invalid parts directory: %w", err)
	}

	err = f.ValidateCreatePath(f.PartsDir)
	if err != nil {
		return fmt.Errorf("failed to create parts directory: %w", err)
	}

	f.Log.Debugf("Parts directory: %s", f.PartsDir)

	return nil
}

func (f *Fileutils) RemovePartsOrDirectory(u *utils.Utils, keepParts bool, partsDir string, appRoot string, prefixParts string) error {
    if !keepParts {
        sanitizedPartsDir := u.SanitizePath(partsDir)  // Ensure `u` or your utility is accessible here or replace appropriately.
        sanitizedAppRoot := u.SanitizePath(appRoot)

        f.Log.Debugw("Removing parts directory:",
            "Directory", partsDir,
            "Root directory", appRoot,
        )

        // If sanitizedPartsDir matches sanitizedAppRoot, remove only files with a specific prefix
        if sanitizedPartsDir == sanitizedAppRoot {
            files, err := os.ReadDir(sanitizedPartsDir)
            if err != nil {
                return fmt.Errorf("failed to read directory: %w", err)
            }
			// Remove files with a specific prefix
			err = f.removeFiles(files, prefixParts, sanitizedPartsDir)
			if err != nil {
				return fmt.Errorf("failed to remove files: %w", err)
			}
        } else if sanitizedPartsDir != "" && sanitizedPartsDir != "." && sanitizedPartsDir != "./" {
            // Remove the directory and all its contents
            err := os.RemoveAll(partsDir)
            if err != nil {
                return fmt.Errorf("failed to remove parts directory: %w", err)
            }
        }
    }
    return nil
}

func (f *Fileutils) removeFiles(files []fs.DirEntry, prefixParts string, sanitizedPartsDir string) error {
	for _, file := range files {
		if strings.HasPrefix(file.Name(), prefixParts) {
			err := os.Remove(filepath.Join(sanitizedPartsDir, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to remove file: %w", err)
			}
		}
	}
	return nil
}

func (f *Fileutils) LoadConfig(v *viper.Viper, configName string, configPath string) error {
	if f.PathExists(configPath) {
		v.SetConfigName(configName) // Name of config file (without extension)
		v.AddConfigPath(configPath) // Path to look for the config file in

		err := v.ReadInConfig() // Find and read the config file
		if err != nil { // Handle errors reading the config file
			return fmt.Errorf("fatal error config file: %w", err)
		}
	} else {
		return fmt.Errorf("config file does not exist: %s", configPath)
	}
	return nil
}