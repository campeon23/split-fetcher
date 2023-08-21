package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500 B"},
		{1500, "1.5 KiB"},
		//... add more cases
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, FormatFileSize(tt.input))
	}
}

func TestFormatPercentage(t *testing.T) {
	assert.Equal(t, "50.0%", FormatPercentage(50, 100))
	assert.Equal(t, "100.0%", FormatPercentage(100, 100))
	//... add more cases
}

func TestFormatSpeed(t *testing.T) {
	// Test with some random values
	assert.Contains(t, FormatSpeed(1024, 1000000), "KiB/s")
	//... add more cases
}

func TestTrimLeadingSymbols(t *testing.T) {
	utils := NewUtils("", nil)
	assert.Equal(t, "Test", utils.TrimLeadingSymbols("$$$Test"))
	assert.Equal(t, "123Test", utils.TrimLeadingSymbols("123Test"))
	//... add more cases
}

func TestGenerateTimestamp(t *testing.T) {
	utils := NewUtils("", nil)
	first := utils.GenerateTimestamp()
	time.Sleep(1 * time.Millisecond)
	second := utils.GenerateTimestamp()
	assert.True(t, first < second, "Expect second timestamp to be greater")
}

func TestParseLink(t *testing.T) {
	utils := NewUtils("", nil)
	resource, key, value, err := utils.ParseLink("http://example.com/resource?debug=true")
	assert.NoError(t, err)
	assert.Equal(t, "resource", resource)
	assert.Equal(t, "debug", key)
	assert.Equal(t, "true", value)
	//... add more cases
}