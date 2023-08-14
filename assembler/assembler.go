package assembler

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/campeon23/multi-source-downloader/fileutils"
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
	f := fileutils.NewFileutils(a.PartsDir, a.PrefixParts, a.Log)
	message, err := f.ValidatePath(a.PartsDir)
	if err != nil {
		return errors.New("Failed to validate parts dir path: %v" + err.Error())
	}
	a.Log.Debugw(
		"Part dirs path",
		"message", message,
	)
    // Search for all $prefixParts* files in the current directory 
	//	to proceed to assemble the final file
	if f.PathExists(a.PartsDir) {
		absPartsDirPath, err := filepath.Abs(a.PartsDir)
		if err != nil {
			return errors.New("Failed to obtain absolute path: %v" +  err.Error())
		}
		files, err := filepath.Glob(absPartsDirPath + string(os.PathSeparator) + a.PrefixParts + "*")
		if err != nil {
			return errors.New("error searching for part files: %v" + err.Error())
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

		a.Log.Infow("File downloaded and assembled",
			"file", outFile.Name(),
		)
	} else {
		return fmt.Errorf("error: Could not find the parts directory")
	}
	return nil
}

func (a *Assembler) PrepareAssemblyEnviroment(outputFile string, manifestContent []byte) (manifest.DownloadManifest, *os.File, string, error) {
	f := fileutils.NewFileutils(a.PartsDir, a.PrefixParts, a.Log)
	m := manifest.NewManifest(a.PartsDir, a.PrefixParts, a.Log)

	// Validate the path of output file
	// message, err := f.ValidatePath(outputFile)
	// if err != nil {
	// 	f.Log.Fatalw("Found an error validating path string.", err.Error())
	// } else {
	// 	f.Log.Debugw(message)
	// }

	// // Extract the path and filename from the output file
	// filePath, fileName, err := f.ExtractPathAndFilename(outputFile)
	// if err != nil {
	// 	f.Log.Fatalf("Could not parse the string:%v", err.Error())
	// }

	// // Validate the path of the output file
	// if filePath != "" {
	// 	err = f.ValidateCreatePath(filePath)
	// 	if err != nil {
	// 		f.Log.Fatalw("Found an error validating path string: %s", err.Error())
	// 	}
	// }

	// // Decode the JSON content into a map
	// var manifest manifest.DownloadManifest
	// err = json.Unmarshal(manifestContent, &manifest)
	// if err != nil {
	// 	f.Log.Fatalw("Decoding manifest content: ", "error", err.Error())
	// }

	// // Get the output filename from the manifest, if return filename is empty
	// if fileName == "" {
	// 	fileName = manifest.Filename
	// }

	manifest, filePath, fileName, err := m.ExtractManifestFilePathFileName(outputFile, manifestContent)
	if err != nil {
		f.Log.Fatalw("Error: ", err.Error())
	}

	outputPath := filepath.Join(filePath, fileName)

	// Ensure the directory where the output file will be saved exists
	outFile, err := f.CreateFile(outputPath)
	if err != nil {
		f.Log.Fatalw("Error: Found path in string. Faied to create file.", err.Error())
	}
	// defer outFile.Close()

	return manifest, outFile, outputPath, err
}