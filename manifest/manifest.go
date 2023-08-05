package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
)

func getDownloadManifestPath() string {
	if runtime.GOOS == "windows" {
		user, err := user.Current()
		if err != nil {
			log.Fatal("Error fetching user information: ", err)
		}
		return filepath.Join(user.HomeDir, "Appdata", ".multi-source-downloader", ".file_parts_manifest.json")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", ".multi-source-downloader", ".file_parts_manifest.json")
}

func saveDownloadManifest(manifest DownloadManifest) {
	log.Debugw("Initializing Application Directory")

	manifestPath := getDownloadManifestPath()

	// Ensure the directory exists
	manifestDir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		log.Fatal("Error creating config directory: ", err)
	}

	// Debugging: Check if the directory was created
	if pathExists(manifestDir) {
		log.Debugw("Application Directory created successfully", "directory", manifestDir)
	} else {
		log.Warnw("Directory not found", "directory", manifestDir)
	}

	// Before saving the manifest file, check if the file exists and delete it
	if pathExists(manifestPath) {
		log.Debugw("Manifest file exists. Deleting:", "file", manifestPath)
		err := os.Remove(manifestPath)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Infow("Manifest file not found", "file: ", manifestPath)
	}

	file, err := os.Create(manifestPath)
	if err != nil {
		log.Fatal("Error creating manifest file: ", err)
	}
	defer file.Close()

	// Debugging: Check if the file was created
	if _, err := os.Stat(manifestPath); err == nil {
		log.Debugw("File created successfully", "file", manifestPath)
	} else {
		log.Warnw("File not found", "file", manifestPath)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(manifest); err != nil {
		log.Fatal("Error encoding manifest JSON: ", err)
	}

	// On Windows, make the file hidden
	if runtime.GOOS == "windows" {
		cmd := fmt.Sprintf("attrib +h %s", manifestPath)
		if err := exec.Command("cmd", "/C", cmd).Run(); err != nil {
			log.Fatal("Error hiding manifest file: ", err)
		}
	}
}
