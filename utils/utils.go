package utils

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gosuri/uiprogress"

	"github.com/campeon23/split-fetcher/logger"
)

// Define a buffer pool globally to reuse buffers
var BufferPool = &sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4096) // Fixed buffer size for efficient memory usage
		return &b
	},
}

type Utils struct {
	PartsDir 	string
	Log 		logger.LoggerInterface
}

func NewUtils(partsDir string, log logger.LoggerInterface) *Utils {
	return &Utils{
		PartsDir: partsDir,
		Log: log,
	}
}

func (u *Utils) SetLogger(log logger.LoggerInterface) {
    u.Log = log
}

type ProgressWriter struct {
	Bar *uiprogress.Bar
	W   io.Writer
}

func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n, err := pw.W.Write(p)
	pw.Bar.Incr()
	return n, err
}

func FormatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func FormatPercentage(current, total int64) string {
	percentage := float64(current) / float64(total) * 100
	return fmt.Sprintf("%.1f%%", percentage)
}

func FormatSpeed(bytes int64, totalMilliseconds int64) string {
	if totalMilliseconds == 0 {
		totalMilliseconds = 1
	}
	speed := float64(bytes) / (float64(totalMilliseconds) / float64(1000*1000)) // B/s
	const unit = 1024

	if speed < unit {
		return fmt.Sprintf("| %.2f B/s", speed)
	}
	div, exp := unit, 0
	for n := speed / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	unitPrefix := fmt.Sprintf("%ciB/s", "KMGTPE"[exp])
	return fmt.Sprintf("| %.2f %s", speed/float64(div), unitPrefix)
}

func (u *Utils) TrimLeadingSymbols(s string) string {
	for i, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return s[i:]
		}
	}
	return s
}

func (u *Utils) GenerateTimestamp() int64 {
	return time.Now().UnixNano()
}

// ParseLink parses the given link and returns the resource name, query key, and query value.
func (u *Utils) ParseLink(link string) (string, string, string, error) {
	urlLink, err := url.Parse(link)
	if err != nil {
		return "", "", "", err
	}

	// Splitting the path to get the resource name
	pathComponents := strings.Split(urlLink.Path, "/")
	if len(pathComponents) < 1 {
		return "", "", "", fmt.Errorf("invalid path in the URL")
	}
	resource := pathComponents[len(pathComponents)-1]

	// Parsing the query values
	values := urlLink.Query()
	debugValue := values.Get("debug")

	return resource, "debug", debugValue, nil
}

func (u *Utils) SanitizePath(path string) string {
    // Clean the path to remove redundant elements
    cleanedPath := filepath.Clean(path)
    // Remove trailing os.PathSeparator if it exists
    if strings.HasSuffix(cleanedPath, string(os.PathSeparator)) {
        cleanedPath = cleanedPath[:len(cleanedPath)-1]
    }
    return cleanedPath
}
// Method to zero out the memory of a byte slice, to prevent the sensitive data from lingering in memory
func (u *Utils) ZeroMemory(data []byte) {
    zero := make([]byte, len(data))
    copy(data, zero)
}

func (u *Utils) ExtractTimestampFromFilename(filename string) (int64, error) {
	// Regular expression to match the timestamp pattern in the filename
	re := regexp.MustCompile(`-(\d+).json.enc$`)
	matches := re.FindStringSubmatch(filename)
	
	if len(matches) < 2 {
		return 0, fmt.Errorf("timestamp not found in filename")
	}

	// Convert the timestamp string to int64
	timestamp, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	return timestamp, nil
}