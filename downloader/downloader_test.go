package downloader

import (
	"net/http"
	"testing"
)

type FakeHTTPClient struct {
    Response *http.Response
    Err      error
}

func (f *FakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
    return f.Response, f.Err
}

func Test_startsWithHTTP(t *testing.T) {
    tests := []struct {
        input  string
        expect bool
    }{
        {"http://example.com", true},
        {"https://example.com", false},
        {"ftp://example.com", false},
        {"", false},
    }

    for _, tt := range tests {
        t.Run(tt.input, func(t *testing.T) {
            got := startsWithHTTP(tt.input)
            if got != tt.expect {
                t.Errorf("Expected %v, got %v", tt.expect, got)
            }
        })
    }
}
