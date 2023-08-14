package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/logger"
)

type Manifest struct {
	PartsDir		string
	PrefixParts		string
	Log				*logger.Logger
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

func NewManifest(partsDir string, prefixParts string, log *logger.Logger) *Manifest {
	return &Manifest{
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Log: log,
	}
}

func (m *Manifest) GetDownloadManifestPath(fileName string, hash string) (string, error)  {
	// Remove all extensions from the filename, in case file contains multiple extensions or just one
	f := fileutils.NewFileutils(m.PartsDir, m.PrefixParts, m.Log)
	fileName = f.RemoveExtensions(fileName)

	var path string
	if runtime.GOOS == "windows" {
		user, err := user.Current()
		if err != nil {
			return "", errors.New("Error fetching user information: " + err.Error())
		}
		path = filepath.Join(user.HomeDir, "Appdata", ".multi-source-downloader")
	} else {
		path = filepath.Join(os.Getenv("HOME"), ".config", ".multi-source-downloader")
	}

	return filepath.Join(path, fileName+".manifest." + hash + ".json"), nil
}

func (m *Manifest) SaveDownloadManifest(manifest DownloadManifest, fileName string, hash string) error {
	f := fileutils.NewFileutils(m.PartsDir, m.PrefixParts, m.Log)
	m.Log.Debugw("Initializing Config Directory")

	manifestPath, err := m.GetDownloadManifestPath(fileName, hash)
	if err != nil {
		return err
	}

	// Ensure the directory exists
	manifestDir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		return errors.New("Error creating config directory: " + err.Error())
	}

	// Debugging: Check if the directory was created
	if f.PathExists(manifestDir) {
		m.Log.Debugw("Application Directory created successfully", "directory", manifestDir)
	} else {
		m.Log.Warnw("Directory not found", "directory", manifestDir)
	}

	// Before saving the manifest file, check if the file exists and delete it
	if f.PathExists(manifestPath) {
		m.Log.Debugw("Manifest file exists. Deleting:", "file", manifestPath)
		err := os.Remove(manifestPath)
		if err != nil {
			return errors.New("Error deleting manifest file: " + err.Error())
		}
	} else {
		m.Log.Debugw("Manifest file not found", "file: ", manifestPath)
	}

	file, err := os.Create(manifestPath)
	if err != nil {
		return errors.New("Error creating manifest file: " + err.Error())
	}
	defer file.Close()

	// Debugging: Check if the file was created
	if _, err := os.Stat(manifestPath); err == nil {
		m.Log.Debugw("File created successfully", "file", manifestPath)
	} else {
		m.Log.Warnw("File not found", "file", manifestPath)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(manifest); err != nil {
		return errors.New("Error encoding manifest JSON: " + err.Error())
	}

	// On Windows, make the file hidden
	if runtime.GOOS == "windows" {
		cmd := fmt.Sprintf("attrib +h %s", manifestPath)
		if err := exec.Command("cmd", "/C", cmd).Run(); err != nil {
			return errors.New("Error hiding manifest file: " + err.Error())
		}
	}
	return nil
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
