package pprofutils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/assert"
)

// type mockLogger struct {
// 	*logger.Logger
// }

type mockServer struct {}

type MockKeyPressReader struct{}

func (m *mockServer) ListenAndServe() error {
	// Simulate a server error here for testing
    return errors.New("mock error")
}

func (m *mockServer) ListenAndServeTLS(certFile, keyFile string) error {
    return http.ErrServerClosed // This mocks the behavior as if the server was started and then stopped.
}

func (m *mockServer) Shutdown(ctx context.Context) error {
    return nil
}

func (m *MockKeyPressReader) WaitForKeyPress() byte {
    return 's'  // or any other value that would simulate the desired behavior in tests
}

func TestStartServerWithShutdown(t *testing.T) {
	l := logger.InitLogger(true)
	p := NewPprofUtils(l, ":6060")
	p.Server = &mockServer{} // Inject mock server

	// Mock KeyPressReader to simulate 's' keypress immediately
	reader := &MockKeyPressReader{}

	errChan := p.StartServerWithShutdown(":6060", "mockCert", "mockKey", reader)

	select {
	case err := <-errChan:
		fmt.Println("Received error:", err) // for debugging purposes
    	assert.Nil(t, err, "Expected no error but got: %v", err)
	case <-time.After(10 * time.Second):
		assert.Fail(t, "Expected server to shut down by now")
	}
}

