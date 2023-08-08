package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/utils"
)

type Hasher struct {
	Log	*logger.Logger
}

type fileHashes struct {
	Md5    string
	Sha1   string
	Sha256 string
}

func NewHasher(log *logger.Logger) *Hasher {
	return &Hasher{
		Log: log,
	}
}

func (h *Hasher) DownloadAndParseHashFile(shaSumsURL string) (map[string]string, error) {
	u := utils.NewUtils("", h.Log)
	if h.Log == nil {
		fmt.Println("Error: Logger not initialized in hasher!")
		return nil, fmt.Errorf("logger not initialized in hasher")
	}
	resp, err := http.Get(shaSumsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	hashes := make(map[string]string)
	for _, line := range lines {
		if line != "" {
			parts := strings.SplitN(line, " ", 2)
			parts[1] = u.TrimLeadingSymbols(parts[1])
			h.Log.Debugw(
				"Parsing content from hashes file.", 
				"lenght", len(parts), 
				"parts", parts,
			) // Add debug output
			if len(parts) != 2 {
				continue
			}

			hash := strings.TrimSpace(parts[0])
			fileName := strings.TrimSpace(parts[1])

			hashes[fileName] = hash
		}
	}

	h.Log.Debugw(
		"Obtaining hashes from file.", 
		"hashes", hashes,
	) // Add debug output

	return hashes, nil
}

func (h *Hasher) HashFile(path string) (fileHashes, error) {
	file, err := os.Open(path)
	if err != nil {
		return fileHashes{}, err
	}
	defer file.Close()

	hMd5 := md5.New()
	hSha1 := sha1.New()
	hSha256 := sha256.New()

	if _, err := io.Copy(io.MultiWriter(hMd5, hSha1, hSha256), file); err != nil {
		return fileHashes{}, err
	}

	return fileHashes{
		Md5:    hex.EncodeToString(hMd5.Sum(nil)),
		Sha1:   hex.EncodeToString(hSha1.Sum(nil)),
		Sha256: hex.EncodeToString(hSha256.Sum(nil)),
	}, nil
}

// Function to calculate the SHA-256 hash of a file
func (h *Hasher) CalculateSHA256(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (h *Hasher) ValidateFileIntegrity(fileName, originalFileName, hashType, etag string, hash string, ok bool) {
	fileHash, err := h.HashFile(fileName)
	if err != nil {
		h.Log.Fatalw("Error: ", "error", err)
	}

	// Validate the assembled file integrity and authenticity
	switch {
	case hashType == "strong" && (etag == fileHash.Md5 || etag == fileHash.Sha1 || etag == fileHash.Sha256):
		h.Log.Infow("File hash matches Etag obtained from server (strong hash)")
	case hashType == "weak" && strings.HasPrefix(etag, fileHash.Md5):
		h.Log.Infow("File hash matches Etag obtained from server (weak hash))")
	case hashType == "unknown":
		h.Log.Infow("Unknown Etag format, cannot check hash")
	case ok:
		if hash == fileHash.Sha256 || hash == fileHash.Sha1 || hash == fileHash.Md5 {
			h.Log.Infow("File hash matches hash from SHA sums file")
		} else {
			h.Log.Infow("File hash does not match hash from SHA sums file")
		}
	default:
		h.Log.Infow("File hash does not match Etag")
	}
}



