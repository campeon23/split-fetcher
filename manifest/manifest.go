package manifest

import (
	"encoding/json"
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
	Log	*logger.Logger
}

// Adding a new structure to represent the JSON manifest
type DownloadManifest struct {
	UUID             string                `json:"uuid"`
	Version		  	 string                `json:"version"`
	Filename         string                `json:"filename"`
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

func NewManifest(log *logger.Logger) *Manifest {
	return &Manifest{
		Log: log,
	}
}

func (m *Manifest) GetDownloadManifestPath() string {
	if runtime.GOOS == "windows" {
		user, err := user.Current()
		if err != nil {
			m.Log.Fatal("Error fetching user information: ", err)
		}
		return filepath.Join(user.HomeDir, "Appdata", ".multi-source-downloader", ".file_parts_manifest.json")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", ".multi-source-downloader", ".file_parts_manifest.json")
}

func (m *Manifest) SaveDownloadManifest(manifest DownloadManifest) {
	m.Log.Debugw("Initializing Config Directory")

	manifestPath := m.GetDownloadManifestPath()

	// Ensure the directory exists
	manifestDir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		m.Log.Fatal("Error creating config directory: ", err)
	}

	// Debugging: Check if the directory was created
	if fileutils.PathExists(manifestDir) {
		m.Log.Debugw("Application Directory created successfully", "directory", manifestDir)
	} else {
		m.Log.Warnw("Directory not found", "directory", manifestDir)
	}

	// Before saving the manifest file, check if the file exists and delete it
	if fileutils.PathExists(manifestPath) {
		m.Log.Debugw("Manifest file exists. Deleting:", "file", manifestPath)
		err := os.Remove(manifestPath)
		if err != nil {
			m.Log.Fatal("Manifest file does not exists: ", "error", err.Error())
		}
	} else {
		m.Log.Infow("Manifest file not found", "file: ", manifestPath)
	}

	file, err := os.Create(manifestPath)
	if err != nil {
		m.Log.Fatal("Error creating manifest file: ", err)
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
		m.Log.Fatal("Error encoding manifest JSON: ", err)
	}

	// On Windows, make the file hidden
	if runtime.GOOS == "windows" {
		cmd := fmt.Sprintf("attrib +h %s", manifestPath)
		if err := exec.Command("cmd", "/C", cmd).Run(); err != nil {
			m.Log.Fatal("Error hiding manifest file: ", err)
		}
	}
}
