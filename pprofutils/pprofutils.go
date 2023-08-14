package pprofutils

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/gocolly/colly"
	"github.com/spf13/viper"

	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/utils"
)

var (
	wg 	sync.WaitGroup
)

type PprofUtils struct {
	Log	*logger.Logger
	errCh chan error // shared error channel
}

func NewPprofUtils(log *logger.Logger) *PprofUtils {
	return &PprofUtils{
		Log: log,
		errCh: make(chan error, 1), // Initialize error channel
	}
}

func (p *PprofUtils) GetErrorChannel() chan error {
	return p.errCh
}

func (p *PprofUtils) StartServerWithShutdown(addr, certPath, keyPath string) chan error {
	srv := &http.Server{
		Addr: addr,
	}

	// Handle OS signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTSTP)

	// Listen for 's' keypress
	keyPressChan := make(chan bool, 1)
	go func() {
		for {
			var key byte
			fmt.Scanf("%c", &key)
			if key == 's' {
				keyPressChan <- true
			}
		}
	}()

	// Start server
	go func() {
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != http.ErrServerClosed {
			p.errCh <- fmt.Errorf("server error: %w" +  err.Error())
		}
	}()

	// Block until signal or keypress is received
	select {
	case <-signalChan:
		p.Log.Infow("Received an interrupt, stopping services...")
	case <-keyPressChan:
		p.Log.Infow("Received 's' keypress, stopping services...")
	}

	// Gracefully shutdown the server
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(timeoutCtx); err != nil {
		p.errCh <- fmt.Errorf("server shutdown error: %w" + err.Error())
	} else {
		p.Log.Infow("server gracefully stopped.")
	}

	// Wait for pprof server to shutdown gracefully if it was started
	wg.Wait()

	select {
	case err := <-p.errCh:
		if err != nil {
			return p.errCh // Return the channel with the error
		}
		close(p.errCh)
		return nil
	default:
		close(p.errCh)
		return nil
	}
}

func (p *PprofUtils) StartPprof() chan error {
	wg.Add(1)

	certPath := "./certs/pprof_cert.pem"
	keyPath := "./certs/pprof_key.pem"

	p.Log.Infow("Starting pprof server on :6060")

	go func() {
		defer wg.Done()
		
		// Start the HTTP server with graceful shutdown using TLS
		serverErrCh := p.StartServerWithShutdown(":6060", certPath, keyPath)
		// If server encounters error, pass it to our errCh
		select {
		case err := <-serverErrCh:
			p.errCh <- err
		default:
		}
	}()

	return nil
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
	// This will bypass SSL certificate verification (useful for local development)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	const baseURL = "https://localhost:6060/debug/pprof/" // Assuming you're running the pprof locally
	var fileName string
	var err error

	// Check if debug directory exists; if not, create it
	if _, err := os.Stat("debug"); os.IsNotExist(err) {
		if err := os.Mkdir("debug", 0755); err != nil {
			p.Log.Printf("Failed to create directory: %v", err)
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
		resp, err := http.Get(baseURL + link)
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
				p.Log.Errorf("error creating gzip reader:", err)
				return
			}
			defer gzipReader.Close()
			reader = gzipReader
		}

		// Read response body
		data, err := io.ReadAll(reader)
		if err != nil {
			p.Log.Errorf("error reading response body:", err)
			return
		}

		// Check if the content type is binary
		if contentType == "application/octet-stream" {
			p.Log.Debugf("Warning: Saving binary profile data for %s", link)
		} else if contentType != "text/plain" {
			p.Log.Debugf("Warning: Unknown content type %s for %s", contentType, link)
		}

		resource, dumpType, value, err := u.ParseLink(link)
		if err != nil {
			p.Log.Errorf("Error:", err)
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