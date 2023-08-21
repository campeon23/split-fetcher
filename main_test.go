package main

import (
	"os"
	"testing"

	"github.com/campeon23/multi-source-downloader/hasher"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/spf13/viper"
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
// 	// Mock Assembler
// 	ma := new(MockedAssembler)
// 	ma.On("NewAssembler", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(ma)

// 	// Mock Downloader
// 	md := new(MockedDownloader)
// 	// Set up its expected method calls. For instance:
// 	// md.On("InitDownloadAndParseHashFile", mock.Anything, mock.Anything).Return(someReturnTypeInstance, nil)
// 	md.On("InitDownloadAndParseHashFile", mock.AnythingOfType("*hasher.Hasher"), "http://shaSumsURL").Return(map[string]string{"key": "value"}, nil)

// 	// Inject these mocks into wherever they're used. This depends on your application structure.
// 	// For example, if the run function takes these as arguments or they're global variables, make sure to set them.
// 	// If they're initialized inside functions, consider refactoring to allow for dependency injection.

// 	// Mock Logger
// 	// ml := new(MockedLogger)

// 	ml := logger.InitLogger(true)

// 	// IMPORTANT: Set the mocked logger to the downloader.
//     md.SetLogger(ml)  // Assuming you've implemented the SetLogger method.

// 	run(1, "http://shaSumsURL", "http://urlFile", 2, "/tmp/parts", false, "prefix", "outputFile")

// 	ma.AssertExpectations(t)
// 	// Similarly, assert for Logger and Downloader if needed.

// }

func TestInitConfig(t *testing.T) {
	os.Setenv("URL", "http://example.com")
	initConfig()
	if viper.GetString("url") != "http://example.com" {
		t.Errorf("Expected URL from env variable, got %s", viper.GetString("url"))
	}
}