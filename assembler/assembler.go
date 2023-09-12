package assembler

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/campeon23/split-fetcher/fileutils"
	"github.com/campeon23/split-fetcher/hasher"
	"github.com/campeon23/split-fetcher/logger"
	"github.com/campeon23/split-fetcher/manifest"
)

type Assembler struct {
	NumParts 	int
	PartsDir 	string
	PrefixParts string
	KeepParts 	bool
	Timestamp	int64
	Log			logger.LoggerInterface
}

func (a *Assembler) SetLogger(log logger.LoggerInterface) {
    a.Log = log
}

func NewAssembler(numParts int, partsDir string, keepParts bool, prefixParts string, timestamp int64, log logger.LoggerInterface) *Assembler {
	return &Assembler{
		NumParts: numParts,
		PartsDir: partsDir,
		KeepParts: keepParts,
		PrefixParts: prefixParts,
		Timestamp: timestamp,
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

		files = a.sortPartFiles(files, hasher, manifest)

		outFile = a.combineSortedFiles(files, outFile, size, rangeSize)

		a.Log.Infow("File downloaded and assembled",
			"file", outFile.Name(),
		)
	} else {
		return fmt.Errorf("error: Could not find the parts directory")
	}
	return nil
}

func (a *Assembler) sortPartFiles(files []string, hasher hasher.Hasher, manifest manifest.DownloadManifest) []string {
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
	return files
} 

func (a *Assembler) combineSortedFiles(files []string, outFile *os.File, size int, rangeSize int) *os.File {
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

		a.validatePartFileCompletion(i, copied, size, rangeSize)

		partFile.Close()
		if !a.KeepParts { // If keepParts is false, remove the part file
			// Remove manifest file and leave only the encrypted one
			err = os.Remove(file)
			if err != nil {
				a.Log.Fatalw("Removing part file: ", "error", err.Error())
			}
		}
	}
	return outFile
}

func (a *Assembler) validatePartFileCompletion(i int, copied int64, size int, rangeSize int){
	if size != 0 && rangeSize != 0 {
		if i != a.NumParts-1 && copied != int64(rangeSize) {
			a.Log.Fatalw("Error: File part not completely copied")
		} else if i == a.NumParts-1 && copied != int64(size)-int64(rangeSize)*int64(a.NumParts-1) {
			a.Log.Fatalw("Error: Last file part not completely copied")
		}
	}
}

func (a *Assembler) PrepareAssemblyEnviroment(outputFile string, manifestContent []byte) (manifest.DownloadManifest, *os.File, string, error) {
	f := fileutils.NewFileutils(a.PartsDir, a.PrefixParts, a.Log)
	m := manifest.NewManifest(a.PartsDir, a.PrefixParts, a.Timestamp, a.Log)

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