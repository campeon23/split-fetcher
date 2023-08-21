package pprofutils

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"github.com/gocolly/colly"
	"github.com/spf13/viper"

	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/utils"
)

const (
	port = ":6060"
	certPath = "./certs/pprof_cert.pem"
	keyPath = "./certs/pprof_key.pem"
	baseURL = "https://localhost" + port + "/debug/pprof/" // Assuming you're running the pprof locally
)

type Server interface {
	ListenAndServeTLS(certFile, keyFile string) error
	Shutdown(ctx context.Context) error
}
 
type PprofUtils struct {
	Log		logger.LoggerInterface
	ErrCh 	chan error // shared error channel
	Server 	Server
	Addr 	string
	wg      sync.WaitGroup
	errChMu sync.Mutex // Add a mutex for synchronizing error channel writes
}

func (p *PprofUtils) SetLogger(log logger.LoggerInterface) {
    p.Log = log
}

type KeyPressReader interface {
    WaitForKeyPress() byte
}

type RealKeyPressReader struct{}

func (r *RealKeyPressReader) WaitForKeyPress() byte {
    var key byte
    fmt.Scanf("%c", &key)
    return key
}

func (p *PprofUtils) writeToErrCh(err error) {
	p.errChMu.Lock() // Lock before writing to the error channel
	defer p.errChMu.Unlock()

	select {
	case p.ErrCh <- err:
	default:
	}
}

func NewPprofUtils(log logger.LoggerInterface, addr string) *PprofUtils {
	return &PprofUtils{
		Log: log,
		ErrCh: make(chan error, 1), // Initialize error channel
		Server: &http.Server{
			Addr: addr,
		},
		Addr: addr,
	}
}

func (p *PprofUtils) GetErrorChannel() chan error {
	return p.ErrCh
}

func (p *PprofUtils) StartServerWithShutdown(addr string, certPath string, keyPath string, reader KeyPressReader) chan error {
    // Handle OS signals
	osSignalChan := p.handleOSSignals() // Initialize the OS signal handling

	// Your existing logic for keypress
	keyPressChan := make(chan bool, 1)
	go func() {
		for {
			key := reader.WaitForKeyPress()
			if key == 's' {
				keyPressChan <- true
			}
		}
	}()

	// Start server
	go func() {
		if err := p.Server.ListenAndServeTLS(certPath, keyPath); err != http.ErrServerClosed {
			p.writeToErrCh(fmt.Errorf("server error: %w", err)) // Use the new method to write to the error channel
		}
	}()

	// Block until signal or keypress is received
	select {
	case <-osSignalChan:
		p.Log.Infow("Received an interrupt, stopping services...")
		// Handle the signal here (like clean up resources, etc.)
		os.Exit(0)
	case <-keyPressChan:
		p.Log.Infow("Received 's' keypress, stopping services...")
	}

	// Gracefully shutdown the server
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Server.Shutdown(timeoutCtx); err != nil {
		p.writeToErrCh(fmt.Errorf("server shutdown error: %w", err)) // Use the new method to write to the error channel
	} else {
		p.Log.Infow("server gracefully stopped.")
		p.writeToErrCh(nil)  // Use the new method to write to the error channel
	}

	// Wait for pprof server to shutdown gracefully if it was started
	p.wg.Wait()

	return p.ErrCh
}

func (p *PprofUtils) StartPprof() chan error {
	p.wg.Add(1)

	p.Log.Infow("Starting pprof server", "port", port)

	go func() {
		defer p.wg.Done()
		
		// Start the HTTP server with graceful shutdown using TLS
		 serverErrCh := p.StartServerWithShutdown(port, certPath, keyPath, &RealKeyPressReader{})
		// If server encounters error, pass it to our errCh
		select {
		case err := <-serverErrCh:
			p.ErrCh <- err
		default:
		}
	}()

	return p.ErrCh
}

func (p *PprofUtils) DumpDebugPProf() error {
	// Retrieve the values of your flags
	urlFile := viper.GetString("url")
	outputFile := viper.GetString("output")
	partsDir := viper.GetString("part-dirs")
	prefixParts := viper.GetString("prefix-parts")

	c := colly.NewCollector()
	f := fileutils.NewFileutils(partsDir, prefixParts, p.Log)
	u := utils.NewUtils("", p.Log)

	var fileName string
	var err error

	// Check if debug directory exists; if not, create it
	if _, err := os.Stat("debug"); os.IsNotExist(err) {
		if err := os.Mkdir("debug", 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	if outputFile != "" {
		// Extract the path and filename from the output file
		_, fileName, err = f.ExtractPathAndFilename(outputFile)
		if err != nil {
			return fmt.Errorf("could not parse the string:%v", err.Error())
		}
	} else {
		parsedURL, err := url.Parse(urlFile)
		if err != nil {
			return fmt.Errorf("could not parse the url:%v", err.Error())
		}

		// Get the file name from the URL
		fileName = path.Base(parsedURL.Path)
	}

	// Callback when a visited link is found
	c.OnHTML("a[href]", func(t *colly.HTMLElement) {
		link := t.Attr("href")
		// Send GET request to the link with query parameter
		resp, err := http.DefaultClient.Get(baseURL + link)
		if err != nil {
			p.Log.Errorf("failed querying %s: %v", baseURL, err)
			return
		}
		defer resp.Body.Close()

		var reader io.Reader = resp.Body
		contentType := resp.Header.Get("Content-Type")

		// If the content is gzip compressed, then decompress it
		if resp.Header.Get("Content-Encoding") == "gzip" {
			gzipReader, err := gzip.NewReader(resp.Body)
			if err != nil {
				p.Log.Errorf("error creating gzip reader: %v", err)
				return
			}
			defer gzipReader.Close()
			reader = gzipReader
		}

		// Read response body
		data, err := io.ReadAll(reader)
		if err != nil {
			p.Log.Errorf("error reading response body: %v", err)
			return
		}

		// Check if the content type is binary
		switch contentType {
		case "application/octet-stream":
			p.Log.Debugf("Warning: Saving binary profile data for %s", link)
		case "text/plain":
		default:
			p.Log.Debugf("Warning: Unknown content type %s for %s", contentType, link)
		}

		resource, dumpType, value, err := u.ParseLink(link)
		if err != nil {
			p.Log.Errorf("Error: %v", err)
			return
		}

		dumpName := fmt.Sprintf("%s_%s_%s_%s_%d", fileName, resource, dumpType, value, u.GenerateTimestamp())

		// Write to file in the debug directory
		err = os.WriteFile("debug/"+dumpName, data, 0644)
		if err != nil {
			p.Log.Errorf("Error writing to file: %v", err)
			return
		}

		p.Log.Debugw(
			"Wrote file to debug directory",
			"file", dumpName,
			"baseURL", baseURL,
			"response", resp,
		)
	})
	err = c.Visit(baseURL)
	if err != nil {
		return fmt.Errorf("error visiting %s: %v", baseURL, err)
	}
	return nil
}