package assembler

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/manifest"
)

type Assembler struct {
	NumParts 	int
	PartsDir 	string
	PrefixParts string
	KeepParts 	bool
	Log			*logger.Logger
}

func NewAssembler(numParts int, partsDir string, keepParts bool, prefixParts string, log *logger.Logger) *Assembler {
	return &Assembler{
		NumParts: numParts,
		PartsDir: partsDir,
		KeepParts: keepParts,
		PrefixParts: prefixParts,
		Log: log,
	}
}

func (a *Assembler) AssembleFileFromParts(manifest manifest.DownloadManifest, outFile *os.File, size int, rangeSize int, hasher hasher.Hasher) error {
    // Search for all $prefixParts* files in the current directory 
	//	to proceed to assemble the final file
	files, err := filepath.Glob(a.PartsDir + a.PrefixParts + "*")
	if err != nil {
		return errors.New("error searching for part files: " + err.Error())
	}

	sort.Slice(files, func(i, j int) bool {
		hashI, err := hasher.CalculateSHA256(files[i])
		if err != nil {
			a.Log.Fatalw("Calculating hash: ", "error", err.Error())
		}
		hashJ, err := hasher.CalculateSHA256(files[j])
		if err != nil {
			a.Log.Fatalw("Calculating hash: ", "error", err.Error())
		}

		// Get the part numbers from the .file_parts_manifest.json file
		numI, numJ := -1, -1
		for _, part := range manifest.DownloadedParts {
			if part.FileHash == hashI {
				numI = part.PartNumber
			}
			if part.FileHash == hashJ {
				numJ = part.PartNumber
			}
		}

		// Compare the part numbers to determine the sorting order
		return numI < numJ
	})


	// Iterate through `files` and read and combine them in the sorted order
	for i, file := range files {
		a.Log.Debugw(
			"Downloaded part", 
			"part file",	i+1,
			"file", 		file,
		) // Print the part being assembled. Debug output
		partFile, err := os.Open(file)
		if err != nil {
			a.Log.Fatalw("Error: failed oppeing part file.", "error", err)
		}

		copied, err := io.Copy(outFile, partFile)
		if err != nil {
			a.Log.Fatalw("Error: ", err)
		}

		if size != 0 && rangeSize != 0 {
			if i != a.NumParts-1 && copied != int64(rangeSize) {
				a.Log.Fatalw("Error: File part not completely copied")
			} else if i == a.NumParts-1 && copied != int64(size)-int64(rangeSize)*int64(a.NumParts-1) {
				a.Log.Fatalw("Error: Last file part not completely copied")
			}
		}

		partFile.Close()
		if !a.KeepParts { // If keepParts is false, remove the part file
			// Remove manifest file and leave only the encrypted one
			err = os.Remove(file)
			if err != nil {
				a.Log.Fatalw("Removing part file: ", "error", err.Error())
			}
		}
	}

	a.Log.Infow("File downloaded and assembled")

	return nil
}