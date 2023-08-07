package utils

import (
	"fmt"
	"io"
	"sync"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/gosuri/uiprogress"
)

// Define a buffer pool globally to reuse buffers
var BufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096) // Fixed buffer size for efficient memory usage
	},
}

type Utils struct {
	PartsDir 	string
	Log			*logger.Logger
}

func NewUtils(partsDir string, log *logger.Logger) *Utils {
	return &Utils{
		PartsDir: partsDir,
		Log: log,
	}
}

type ProgressWriter struct {
	Bar *uiprogress.Bar
	W   io.Writer
}

func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.Bar.Set(pw.Bar.Current() + n)
	return pw.W.Write(p)
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