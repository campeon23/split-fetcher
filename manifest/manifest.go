package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/campeon23/split-fetcher/fileutils"
	"github.com/campeon23/split-fetcher/logger"
)

type Manifest struct {
	PartsDir		string
	PrefixParts		string
	TimeStamp		int64
	Log				logger.LoggerInterface
}

// Adding a new structure to represent the JSON manifest
type DownloadManifest struct {
	UUID             string                `json:"uuid"`
	Version		  	 string                `json:"version"`
	Filename         string                `json:"filename"`
	FileHash		 string                `json:"file_hash"`
	URL              string                `json:"url"`
	Etag			 string                `json:"etag"`
	HashType		 string                `json:"hash_type"`
	PartsDir		 string				   `json:"parts_dir"`
	PrefixParts		 string				   `json:"prefix_parts"`
	Size			 int                   `json:"size"`
	NumParts         int                   `json:"num_parts"`
	RangeSize		 int                   `json:"range_size"`
	DownloadedParts  []DownloadedPart      `json:"downloaded_parts"`
}

type DownloadedPart struct {
	PartNumber int    `json:"part_number"`
	FileHash   string `json:"file_hash"`
	Timestamp  int64  `json:"timestamp"`
	PartFile   string `json:"part_file"`
}

func NewManifest(partsDir string, prefixParts string, timestamp int64, log logger.LoggerInterface) *Manifest {
	return &Manifest{
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		TimeStamp: timestamp,
		Log: log,
	}
}

func (m *Manifest) SetLogger(log logger.LoggerInterface) {
    m.Log = log
}

func (m *Manifest) ManifestPath(fileName string, hash string) (string, error)  {
	// Remove all extensions from the filename, in case file contains multiple extensions or just one
	f := fileutils.NewFileutils(m.PartsDir, m.PrefixParts, m.Log)
	fileName = f.RemoveExtensions(fileName)

	var path string
	if runtime.GOOS == "windows" {
		user, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("error fetching user information: %w", err)
		}
		path = filepath.Join(user.HomeDir, "Appdata", ".split-fetcher")
	} else {
		path = filepath.Join(os.Getenv("HOME"), ".config", ".split-fetcher")
	}

	return filepath.Join(path, fileName + "-manifest-" + hash + "-" + strconv.FormatInt(m.TimeStamp, 10) + ".json"), nil
}

func (m *Manifest) DownloadManifestObject(manifest DownloadManifest, fileName string, hash string) ([] byte, error) {
	f := fileutils.NewFileutils(m.PartsDir, m.PrefixParts, m.Log)
	m.Log.Debugw("Initializing Config Directory")

	manifestPath, err := m.ManifestPath(fileName, hash)
	if err != nil {
		return nil, fmt.Errorf("error getting manifest path: %w", err)
	}

	// Ensure the directory exists
	manifestDir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		return nil, fmt.Errorf("error creating config directory: %w", err)
	}

	// Debugging: Check if the directory was created
	if f.PathExists(manifestDir) {
		m.Log.Debugw("Application Directory created successfully", "directory", filepath.Base(manifestDir))
	} else {
		m.Log.Warnw("Directory not found", "directory", filepath.Base(manifestDir))
	}

	// Before saving the manifest file, check if the file exists and delete it
	if f.PathExists(manifestPath) {
		m.Log.Debugw("Manifest file exists. Deleting:", "file", filepath.Base(manifestPath))
		err := os.Remove(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("error deleting manifest file: %w", err)
		}
	} else {
		m.Log.Debugw("Manifest file not found", "file: ", filepath.Base(manifestPath))
	}

	encodedData, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("error encoding manifest JSON: %w", err)
	}

	return encodedData, nil
}

func (m *Manifest) ExtractManifestFilePathFileName(outputFile string, manifestContent []byte) (DownloadManifest, string, string, error) {
	f := fileutils.NewFileutils(m.PartsDir, m.PrefixParts, m.Log)
	// Validate the path of output file
	message, err := f.ValidatePath(outputFile)
	if err != nil {
		f.Log.Fatalw("Found an error validating path string.", err.Error())
	} else {
		f.Log.Debugw(message)
	}

	// Extract the path and filename from the output file
	filePath, fileName, err := f.ExtractPathAndFilename(outputFile)
	if err != nil {
		f.Log.Fatalf("Could not parse the string:%v", err.Error())
	}

	// Validate the path of the output file
	if filePath != "" {
		err = f.ValidateCreatePath(filePath)
		if err != nil {
			f.Log.Fatalw("Found an error validating path string: %s", err.Error())
		}
	}

	// Decode the JSON content into a map
	var manifest DownloadManifest
	err = json.Unmarshal(manifestContent, &manifest)
	if err != nil {
		f.Log.Fatalw("Decoding manifest content: ", "error", err.Error())
	}

	// Get the output filename from the manifest, if return filename is empty
	if fileName == "" {
		fileName = manifest.Filename
	}

	return manifest, filePath, fileName, err
}
