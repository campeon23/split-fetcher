package main

import (
	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/mock"
)

// Mocked version of assembler
type MockedAssembler struct {
	mock.Mock
}

type MockedLogger struct {
    Log			logger.LoggerInterface // pretend to embed original logger
    mock.Mock
}

type MockedDownloader struct {
	Log			logger.LoggerInterface // pretend to embed original logger
	mock.Mock
}

type MockedEncryption struct {
	mock.Mock
}

func (m *MockedLogger) Sync() {
	m.Called()
}

func (m *MockedLogger) Infow(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

func (m *MockedLogger) Errorf(template string, args ...interface{}) {
	m.Called(template, args)
}

func (m *MockedLogger) Printf(template string, args ...interface{}) {
	m.Called(template, args)
}

func (m *MockedLogger) Debugw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

func (m *MockedLogger) Debugf(template string, args ...interface{}) {
	m.Called(template, args)
}

func (m *MockedLogger) Warnw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

func (m *MockedLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
}

func (m *MockedLogger) Fatalf(template string, args ...interface{}) {
	m.Called(template, args)
}

func (m *MockedDownloader) SetLogger(log logger.LoggerInterface) {
    m.Log = log
}

func (m *MockedDownloader) InitDownloadAndParseHashFile(h hasher.Hasher, shaSumsURL string) (map[string]string, error) {
	// Implement this based on how your Downloader's method looks.
	args := m.Called(h, shaSumsURL)
	return args.Get(0).(map[string]string), args.Error(1)
}


func (m *MockedAssembler) NewAssembler(numParts int, partsDir string, keepParts bool, prefixParts string, log *logger.Logger) *MockedAssembler {
	args := m.Called(numParts, partsDir, keepParts, prefixParts, log)
	return args.Get(0).(*MockedAssembler)
}

// func TestRun(t *testing.T) {
// 	log := logger.InitLogger(false)
// 	// Mock Assembler
// 	ma := new(MockedAssembler)
// 	ma.On("NewAssembler", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(ma)

// 	// Mock Downloader
// 	md := new(MockedDownloader)
// 	md.On("InitDownloadAndParseHashFile", mock.AnythingOfType("*hasher.Hasher"), "http://shaSumsURL").Return(map[string]string{"key": "value"}, nil)

// 	// Mock Encryption
// 	me := new(MockedEncryption)
// 	// Mock the Encrypt method
// 	me.On("Encrypt", mock.AnythingOfType("[]byte"), "someKey").Return([]byte("encryptedData"), nil)
// 	// Mock the Decrypt method
// 	me.On("Decrypt", mock.AnythingOfType("[]byte"), "someKey").Return([]byte("originalData"), nil)

// 	// // Mock FileUtils
// 	// mf := new(MockedFileutils)
// 	// // Mock its methods here

// 	// // Mock Hasher
// 	// mh := new(MockedHasher)
// 	// // Mock its methods here

// 	// // Mock Utils
// 	// mu := new(MockedUtils)
// 	// // Mock its methods here

// 	// Mock Logger
// 	ml := new(MockedLogger)
// 	ml.On("Infow", "Initializing HTTP request", mock.Anything).Return()
// 	ml.On("Debugw", "Creating HTTP request for URL", mock.Anything).Return()
// 	ml.On("Fatalf", "Failed, encountered and error.", mock.Anything).Return()


// 	// Assuming these are the right mock methods
// 	// Set the mocked logger to the downloader.
// 	md.SetLogger(ml)  

// 	// Assuming AppConfig doesn't need mocking and it's just configuration
// 	cfg := &AppConfig{
// 		// ... populate needed fields here ...
// 		maxConcurrentConnections: viper.GetInt("max-connections"),
// 		shaSumsURL 				: viper.GetString("sha-sums"),
// 		urlFile 				: viper.GetString("url"),
// 		numParts 				: viper.GetInt("num-parts"),
// 		verbose 				: viper.GetBool("verbose"),
// 		manifestFile 			: viper.GetString("manifest-file"),
// 		decryptManifest 		: viper.GetBool("decrypt-manifest"),
//         downloadOnly 			: viper.GetBool("download-only"),
//         assembleOnly 			: viper.GetBool("assemble-only"),
//         outputFile 	 			: viper.GetString("output"),
// 		partsDir 	 			: viper.GetString("parts-dir"),
// 		prefixParts	 			: viper.GetString("prefix-parts"),
// 		proxy 		 			: viper.GetString("proxy"),
// 		keepParts 	 			: viper.GetBool("keep-parts"),
// 		enablePprof  			: viper.GetBool("enable-pprof"), // Uncomment if debuging with pprof
// 		log 					: log,
// 	}

// 	run(1, "http://shaSumsURL", "http://urlFile", 2, "/tmp/parts", false, "prefix", "outputFile", ml, cfg)

// 	// Assert that the mocks were called as expected
// 	ma.AssertExpectations(t)
// 	md.AssertExpectations(t)
// 	me.AssertExpectations(t)
// 	// mf.AssertExpectations(t)
// 	// mh.AssertExpectations(t)
// 	// mu.AssertExpectations(t)
// 	ml.AssertExpectations(t)
// }

// func TestInitConfig(t *testing.T) {
// 	cfg := NewAppConfig()
// 	os.Setenv("URL", "http://example.com")
// 	cfg.InitConfig()
// 	if viper.GetString("url") != "http://example.com" {
// 		t.Errorf("Expected URL from env variable, got %s", viper.GetString("url"))
// 	}
// }