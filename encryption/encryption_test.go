package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/assert"
)

const testfile = "testfile.txt"

type MockLogger struct {
	InfoLogs  []string
	DebugLogs []string
	ErrorLogs []string
	FatalLogs []string
	PrintLogs []string
	WarnLogs  []string
	SyncCalls int
}

type MockFileOps struct {
	data 		[]byte
	dataMap 	map[string][]byte
	err 		error
	tempFiles 	[]*os.File
	writtenData  []byte
}

func (m *MockFileOps) GetWrittenData() []byte {
    return m.writtenData
}

func (m *MockFileOps) CleanUp() {
    for _, file := range m.tempFiles {
        os.Remove(file.Name()) // delete the file
        file.Close()           // ensure it's closed
    }
}

func (l *MockLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.InfoLogs = append(l.InfoLogs, msg)
}

func (l *MockLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.DebugLogs = append(l.DebugLogs, msg)
}

func (l *MockLogger) Debugf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.DebugLogs = append(l.DebugLogs, formattedMsg)
}

func (l *MockLogger) Errorf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.ErrorLogs = append(l.ErrorLogs, formattedMsg)
}

func (l *MockLogger) Fatalf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.FatalLogs = append(l.FatalLogs, formattedMsg)
}

func (l *MockLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.FatalLogs = append(l.FatalLogs, msg)
}

func (l *MockLogger) Printf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.PrintLogs = append(l.PrintLogs, formattedMsg)
}

func (l *MockLogger) Sync() {
	fmt.Println("Sync is called!")
	l.SyncCalls++
}

func (l *MockLogger) Warnw(msg string, keysAndValues ...interface{}) {
	// Capture logs if necessary
	l.WarnLogs = append(l.WarnLogs, msg)
}

func (m *MockFileOps) Remove(name string) error {
    return m.err
}

func (m *MockFileOps) Create(name string) (*os.File, error) {
	tmpfile, err := os.CreateTemp("", "mockcreatefile")
	if err != nil {
		return nil, err
	}
	return tmpfile, nil
}

func (m *MockFileOps) ReadFile(name string) ([]byte, error) {
    if data, exists := m.dataMap[name]; exists {
        return data, m.err
    }
    return nil, errors.New("file not found in mock")
}

func (m *MockFileOps) Open(name string) (*os.File, error) {
	// Create a temp file
    tmpfile, err := os.CreateTemp("", "mockfile")
    if err != nil {
        return nil, err
    }

    // Write the mock data into the temp file
    _, err = tmpfile.Write(m.data)
    if err != nil {
        tmpfile.Close()
        return nil, err
    }

    // Seek to the start of the file so it's ready for reading
    _, err = tmpfile.Seek(0, 0)
    if err != nil {
        tmpfile.Close()
        return nil, err
    }

    // Optionally simulate error on opening the file

    m.tempFiles = append(m.tempFiles, tmpfile)
    return tmpfile, nil
}

func (m *MockFileOps) WriteFile(filename string, data []byte, perm os.FileMode) error {
	m.dataMap[filename] = data
	return m.err
}

func EncryptAndComputeHMAC(key []byte, data []byte) ([]byte, []byte) {
	// Add padding to the mock encrypted data
	mockPadding := []byte{4, 4, 4, 4}
    data = append(data, mockPadding...)
	// Add mock IV to the mock encrypted data
    // Mock IV and encryption logic (in this case, reversing data)
    mockIV := []byte("IVIVIVIVIVIVIVIV")
    data = append(mockIV, data...)
    
    encryptedData := make([]byte, len(data))
    copy(encryptedData, data)
    for i, j := 0, len(encryptedData)-1; i < j; i, j = i+1, j-1 {
        encryptedData[i], encryptedData[j] = encryptedData[j], encryptedData[i]
    }
    
    // Compute HMAC
    rhmac := hmac.New(sha256.New, key)
    rhmac.Write(encryptedData)
    mac := rhmac.Sum(nil)
    
    return encryptedData, mac
}

func (m *MockFileOps) WriteEncryptedFile(filename string, key []byte, data []byte, perm os.FileMode) error {
	mockEncryptedData, mockHMAC := EncryptAndComputeHMAC(key, data)
    mockEncryptedData = append(mockEncryptedData, mockHMAC...)
    m.dataMap[filename+".enc"] = mockEncryptedData
    return m.err
}

func (m *MockFileOps) WriteDecryptedFile(filename string, key []byte, data []byte, perm os.FileMode) error {
    // Mock behavior. In this case, simply write the data as is (no decryption)
    m.dataMap[filename] = data // Add ".dec" extension for decrypted files
    return m.err
}

func TestCreateEncryptionKey(t *testing.T) {
	partsDir := "test_data_tmp"
	prefixParts := "part_"

	e := NewEncryption("", "", nil) // Adjust as needed
	l := logger.InitLogger(true)

	currentDir, err := os.Getwd()
	assert.NoErrorf(t, err, "Failed to get current dir: %v", err)

	e.PartsDir = currentDir + string(os.PathSeparator) + partsDir
	e.PrefixParts = prefixParts

	err = os.Mkdir(partsDir, 0755)
	assert.NoErrorf(t, err, "Failed to create test directory: %v", err)
	defer os.RemoveAll(partsDir) // Cleanup

	// Create temp files
	strings := []string{"test1", "test2", "test3"}
	for _, s := range strings {
		tempFile, err := os.CreateTemp(partsDir,  prefixParts + s +"*")
		assert.NoErrorf(t, err, "Failed to create temp file: %v", err)
		_, err = tempFile.WriteString(fmt.Sprintf("Content for %s", s))
		assert.NoErrorf(t, err, "Failed to write to temp file: %v", err)
		tempFile.Close()
	}

	key, err := e.CreateEncryptionKey(strings)

	l.Debugf("key: %v", key)

	assert.NoErrorf(t, err, "Failed to create encryption key: %v", err)
	assert.NotNil(t, key)
	assert.Equal(t, 32, len(key))
}

func TestEncryptFileAndDecryptFile(t *testing.T) {
	partsDir := "test_data_tmp"

	l := logger.InitLogger(true)
	e := NewEncryption("", "", l) // Adjust as needed
	
	currentDir, err := os.Getwd()
	assert.NoErrorf(t, err, "Failed to get current dir: %v", err)

	e.PartsDir = currentDir + string(os.PathSeparator) + partsDir

	err = os.Mkdir(partsDir, 0755)
	assert.NoErrorf(t, err, "Failed to create test directory: %v", err)
	defer os.RemoveAll(partsDir) // Cleanup

	testString := "This is a test string."
	filename := testfile
	encryptedFilename := filename + ".enc"
	decryptedFilename := testfile

	// Create a test file
	err = os.WriteFile(path.Join(e.PartsDir, filename), []byte(testString), 0644)
	assert.NoErrorf(t, err, "Failed to create test file: %v", err)

	// Mocked key for encryption (32 bytes for this example)
	mockKey := []byte("abcdefghijklmnopqrstuvwxyzabcdef") // Change this to the desired key value

	assert.NoErrorf(t, err, "Failed to create encryption key: %v", err)

	// Encrypt the test file
	err = e.EncryptFile(path.Join(e.PartsDir, filename), mockKey)
	assert.NoErrorf(t, err, "Failed to encrypt file: %v", err)
	os.Remove(path.Join(e.PartsDir, filename))

	// Decrypt the file to memory
	decryptedBytes, err := e.DecryptFile(path.Join(e.PartsDir, encryptedFilename), mockKey, false)
	assert.NoErrorf(t, err, "Failed to decrypt file: %v", err)
	assert.Equal(t, testString, string(decryptedBytes))

	// Decrypt the file to disk
	_, err = e.DecryptFile(path.Join(e.PartsDir, encryptedFilename), mockKey, true)
	assert.NoErrorf(t, err, "Failed to decrypt file: %v", err)

	decryptedContent, err := os.ReadFile(path.Join(e.PartsDir, decryptedFilename))
	assert.NoErrorf(t, err, "Failed to read decrypted file: %v", err)
	assert.Equal(t, testString, string(decryptedContent))
}

func TestMockWriteEncryptedFile(t *testing.T) {
    mockFileOps := &MockFileOps{
        dataMap: make(map[string][]byte),
    }
    testContent := []byte("Test content")
    err := mockFileOps.WriteEncryptedFile(testfile, nil, testContent, 0644)
    assert.Nil(t, err)
    _, exists := mockFileOps.dataMap[testfile+".enc"]
    assert.True(t, exists)
}

func TestMockFileOps(t *testing.T) {
    mock := &MockFileOps{
        dataMap: make(map[string][]byte),
    }

    key := make([]byte, 32)    // Making a dummy key
    rand.Read(key)
    data := []byte("Test data to be encrypted")

    err := mock.WriteEncryptedFile(testfile, key, data, 0644)
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Equal(mock.dataMap[testfile+".enc"], data) {
        t.Fatalf("Expected different data in the mock, got the same")
    }
}

func TestEncryptionLogic(t *testing.T) {
    key := make([]byte, 32)
    rand.Read(key)
    

	
	// Initialize a mock logger for testing
	mockLogger := &MockLogger{}
    // Mocking Enhancement: Populate dataMap with expected data.
	plaintext := []byte("This is some test data")
	mockFileOps := &MockFileOps{
		data: plaintext,
		dataMap: map[string][]byte{
			testfile: plaintext,
		},
	}

	e := &Encryption{
		Log: mockLogger,
		FileOps: mockFileOps,
	}

	err := mockFileOps.WriteEncryptedFile(testfile, key, plaintext, 0644)
    assert.Nil(t, err)

    err = e.EncryptFile(testfile, key)
    if err != nil {
        t.Fatal(err)
    }

    encryptedData, err := e.FileOps.ReadFile(testfile+".enc")
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Contains(encryptedData, plaintext) {
        t.Fatalf("Encrypted data should not contain plaintext")
    }
}

func TestEncryptedDataSize(t *testing.T) {
    key := make([]byte, 32)
    rand.Read(key)

	const testfile = testfile
	// Initialize a mock logger for testing
	mockLogger := &MockLogger{}
    // Mocking Enhancement: Populate dataMap with expected data.
	testContent := []byte("This is longer test content.")
	mockFileOps := &MockFileOps{
		data: testContent,
		dataMap: map[string][]byte{
			testfile: testContent,
		},
	}

	e := &Encryption{
		Log: mockLogger,
		FileOps: mockFileOps,
	}

	err := mockFileOps.WriteEncryptedFile(testfile, key, testContent, 0644)
    assert.Nil(t, err)

    err = e.EncryptFile(testfile, key)
    if err != nil {
        t.Fatal(err)
    }

    encryptedData, err := e.FileOps.ReadFile(testfile+".enc")
    if err != nil {
        t.Fatal(err)
    }

    expectedSize := 80
    if len(encryptedData) != expectedSize {
        t.Fatalf("Expected encrypted data of size %d bytes, got %d bytes", expectedSize, len(encryptedData))
    }
}

func TestEncryptLogs(t *testing.T) {
	// Initialize a mock logger for testing
	mockLogger := &MockLogger{}
	// Assertions for logs
	// Here, let's add assertions for the expected logs if necessary.
	// You will need to implement the MockLogger and add methods to capture logs.
	if len(mockLogger.InfoLogs) != 1 || mockLogger.InfoLogs[0] != "Initializing ecryption of manifest file." {
		assert.Empty(t, mockLogger.InfoLogs, "Unexpected info logs: %v", mockLogger.InfoLogs)
	}
	if len(mockLogger.DebugLogs) != 1 || !strings.Contains(mockLogger.DebugLogs[0], "File encrypted successfully and saved as.") {
		assert.Empty(t, mockLogger.DebugLogs, "Unexpected debug logs: %v", mockLogger.DebugLogs)
	}
	if len(mockLogger.ErrorLogs) != 1 || !strings.Contains(mockLogger.ErrorLogs[0], "Error: Failed to create file: create file mock.") {
		assert.Empty(t, mockLogger.ErrorLogs, "Unexpected error logs: %v", mockLogger.ErrorLogs)
	}
	if len(mockLogger.FatalLogs) != 1 || !strings.Contains(mockLogger.FatalLogs[0], "Fatat: Failed to create file: create file mock.") {
		assert.Empty(t, mockLogger.FatalLogs, "Unexpected fatal logs: %v", mockLogger.FatalLogs)
	}
	if len(mockLogger.PrintLogs) != 1 || !strings.Contains(mockLogger.PrintLogs[0], "Print: Failed to create file: create file mock.") {
		assert.Empty(t, mockLogger.PrintLogs, "Unexpected print logs: %v", mockLogger.PrintLogs)
	}
	if len(mockLogger.WarnLogs) != 1 || !strings.Contains(mockLogger.WarnLogs[0], "Warn: Failed to create file: create file mock.") {
		assert.Empty(t, mockLogger.WarnLogs, "Unexpected fatal logs: %v", mockLogger.WarnLogs)
	}
	// if mockLogger.SyncCalls != 1 {
	// 	assert.Failf(t, "Expected Sync to be called once, but was called %d times", strconv.Itoa(mockLogger.SyncCalls))
	// }
}


func TestEncryptFile(t *testing.T) {
	// Initialize a mock logger for testing
	mockLogger := &MockLogger{}
    // Mocking Enhancement: Populate dataMap with expected data.
	testContent := []byte("This is longer test content.")
	mockFileOps := &MockFileOps{
		data: testContent,
		dataMap: map[string][]byte{
			testfile: testContent,
		},
	}

	e := &Encryption{
		Log: mockLogger,
		FileOps: mockFileOps,
	}

	key := []byte("this is a sample key that's 32 bytes..")

	err := mockFileOps.WriteEncryptedFile(testfile, key, testContent, 0644)
    assert.Nil(t, err)

	err = e.EncryptFile(testfile, key)
	if err == nil {
		assert.NotNil(t, err, "Expected an error due to mock os.Create, but got none.")
	}


	// Check if the encrypted file data was saved correctly
	encryptedData, exists := mockFileOps.dataMap[testfile+".enc"]
	assert.True(t, exists, "Encrypted data was not saved with the expected key")

	// Ensure encrypted data isn't equal to the original data
    assert.NotEqual(t, testContent, encryptedData, "Encrypted data should not match original content.")

    // assert.True(t, len(encryptedData) > aes.BlockSize) // At least the IV and some content.
	assert.GreaterOrEqual(t, len(encryptedData), aes.BlockSize, "Encrypted data length is less than expected.")

	// Now, let's check the content of the encrypted file
    encryptedData, _ = mockFileOps.ReadFile(testfile+".enc")

	if len(encryptedData) < aes.BlockSize {
		t.Fatalf("Expected encryptedData to be at least %d bytes, but got %d bytes", aes.BlockSize, len(encryptedData))
	}

    // Split the encrypted file data to extract IV, ciphertext and HMAC
    iv := encryptedData[:aes.BlockSize]
    hmacSize := sha256.Size // This is the size of HMAC when using SHA256

	if len(encryptedData) < aes.BlockSize + hmacSize {
		t.Fatalf("Encrypted data is too short: got %d bytes, but expected at least %d bytes", len(encryptedData), aes.BlockSize + hmacSize)
	}

	ciphertext := encryptedData[:len(encryptedData)-sha256.Size]
	mac := encryptedData[len(encryptedData)-sha256.Size:]

	mockOps, ok := e.FileOps.(*MockFileOps)
	if ok {
		encryptedData = mockOps.GetWrittenData()
		fmt.Println("encryptedData: ", encryptedData)
	} else {
		t.Fatal("Expected FileOps to be of type *MockFileOps")
	}

	// MockFileOps might need to store the written data for retrieval in tests
    encryptedData = mockFileOps.GetWrittenData()
	fmt.Println("encryptedData: ", encryptedData)

    // Assertions for iv, ciphertext, and mac
    assert.Equal(t, aes.BlockSize, len(iv), "Invalid IV length")
    
    // Assuming you have a defined expected ciphertext length
    // expectedCiphertextLen := ... (some logic to define this or a fixed value)
    // assert.Equal(t, expectedCiphertextLen, len(ciphertext), "Invalid ciphertext length")
    
    // Checking if HMAC was generated correctly
    regeneratedHMAC := hmac.New(sha256.New, key)
    regeneratedHMAC.Write(ciphertext)
    expectedMac := regeneratedHMAC.Sum(nil)
    assert.Equal(t, expectedMac, mac, "HMAC does not match the expected value")
}

func TestDecryptFile(t *testing.T) {
	// Mock key and data
	key := []byte("12345678901234567890123456789012")

	// Generate correct HMAC for data
	h := hmac.New(sha256.New, key)
	h.Write([]byte("testdata"))
	expectedMac := h.Sum(nil)

	// Prepare mock data: IV + testdata + HMAC
	mockData := append(append(make([]byte, aes.BlockSize), []byte("testdata")...), expectedMac...)

	tests := []struct {
		name           string
		mockData       []byte
		expectedError  error
	}{
		{
			name:          "Valid HMAC",
			mockData:      mockData,
			expectedError: nil,
		},
		{
			name:          "Invalid HMAC",
			mockData:      append(mockData[:len(mockData)-1], 0x00), // Tamper with the HMAC
			expectedError: errors.New("integrity check failed: HMAC mismatch"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up the encryption with mock dependencies
			mockLogger := &MockLogger{}
			e := &Encryption{
				Log: mockLogger,
				FileOps: &MockFileOps{},
			}

			e.FileOps = &MockFileOps{data: tt.mockData}

			_, err := e.DecryptFile("mockfile.enc", key, false)
			if err == nil {
				assert.NotNil(t, err, "Expected an error due to mock os.Create, but got none")
			}

			// At the end of your tests:
			mockOps, ok := e.FileOps.(*MockFileOps)
			if ok {
				mockOps.CleanUp()
			}
		})
	}
}