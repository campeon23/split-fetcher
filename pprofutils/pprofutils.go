package pprofutils

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"github.com/gocolly/colly"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/utils"
)

type Server interface {
	ListenAndServeTLS(certFile, keyFile string) error
	Shutdown(ctx context.Context) error
}
 
type PprofUtils struct {
	Log			logger.LoggerInterface
	ErrCh 		chan error // shared error channel
	Server 		Server
	SecretToken string
	PprofPort 	string
	CertPath 	string
	KeyPath 	string
	BaseURL		string
	EnablePprof	bool
	wg      	sync.WaitGroup
	errChMu 	sync.Mutex // Add a mutex for synchronizing error channel writes
}

func NewPprofUtils(enablePprof bool, pprofPort string, secretToken string, certPath string, keyPath string, baseURL string, log logger.LoggerInterface, errCh chan error) *PprofUtils {
	return &PprofUtils{
		SecretToken:	secretToken,
		PprofPort:		pprofPort,
		CertPath:		certPath,
		KeyPath:		keyPath,
		BaseURL:		baseURL,
		EnablePprof:	enablePprof,
		// router :		mux.NewRouter(),
		Server: &http.Server{
			Addr: pprofPort,
			// Handler: router,
		},
		Log: log,
		ErrCh: 			errCh, // Initialize error channel
	}
}

func (p *PprofUtils) SetLogger(log logger.LoggerInterface) {
    p.Log = log
}

func LoadConfig(configName string, configPath string) error {
    viper.SetConfigName(configName) // Name of config file (without extension)
    viper.AddConfigPath(configPath) // Path to look for the config file in

    err := viper.ReadInConfig() // Find and read the config file
    if err != nil { // Handle errors reading the config file
        return fmt.Errorf("fatal error config file: %w", err)
    }
	return nil
}

// Add middleware for pprof routes authentication
func (p *PprofUtils) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for a specific header, or use any other authentication method you prefer
		if r.Header.Get("X-DEBUG-TOKEN") != p.SecretToken {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// This function sets up the pprof routes
func (p *PprofUtils) initializePprofRoutes(r *mux.Router) {
	// Register pprof root route without middleware
    r.HandleFunc("/debug/pprof/", pprof.Index)
	// Create subrouter for pprof with auth middleware
	pprofRouter := r.PathPrefix("/debug/pprof/").Subrouter()
    pprofRouter.HandleFunc("/", pprof.Index)
	// Register pprof routes with auth middleware
	pprofRouter.HandleFunc("/allocs", pprof.Handler("allocs").ServeHTTP)
	pprofRouter.HandleFunc("/block", pprof.Handler("block").ServeHTTP)
    pprofRouter.HandleFunc("/cmdline", pprof.Cmdline)
	pprofRouter.HandleFunc("/goroutine", pprof.Handler("goroutine").ServeHTTP)
	pprofRouter.HandleFunc("/heap", pprof.Handler("heap").ServeHTTP)
	pprofRouter.HandleFunc("/mutex", pprof.Handler("mutex").ServeHTTP)
    pprofRouter.HandleFunc("/profile", pprof.Profile)
	pprofRouter.HandleFunc("/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
    pprofRouter.HandleFunc("/symbol", pprof.Symbol)
    pprofRouter.HandleFunc("/trace", pprof.Trace)
	// Add auth middleware to all pprof routes
	pprofRouter.Use(p.authMiddleware)
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

	p.Log.Debugw("Starting pprof server", "port", p.PprofPort)

	go func() {
		defer func() {
		if r := recover(); r != nil {
				fmt.Println("Recovered from panic:", r)
			}
		}()
		defer p.wg.Done()

		router := mux.NewRouter() // Create the router
		p.initializePprofRoutes(router) // Initialize pprof routes

		p.Server = &http.Server{
			Addr:    p.PprofPort,
			Handler: router,
		}
		
		// Start the HTTP server with graceful shutdown using TLS
		serverErrCh := p.StartServerWithShutdown(p.PprofPort, p.CertPath, p.KeyPath, &RealKeyPressReader{})
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

		// Create a new request using http
		req, err := http.NewRequest("GET", p.BaseURL+link, nil)
		if err != nil {
			p.Log.Errorf("failed to create a new request: %v", err)
			return
		}

		// Add custom headers to the request
		req.Header.Add("X-DEBUG-TOKEN", p.SecretToken) // replace YOUR_TOKEN_HERE with the actual token

		// Use http.DefaultClient to send the request
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			p.Log.Errorf("failed querying %s: %v", p.BaseURL, err)
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
			case "text/plain; charset=utf-8":
				p.Log.Debugf("Warning: Saving text/plain profile data for %s", link)
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
		)
	})
	err = c.Visit(p.BaseURL)
	if err != nil {
		return fmt.Errorf("error visiting %s: %v", p.BaseURL, err)
	}
	return nil
}