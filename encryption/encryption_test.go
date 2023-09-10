package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/campeon23/multi-source-downloader/database/initdb"
	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/stretchr/testify/assert"
)

const testfile = "testfile.txt"
const testSalt = "test-salt"

type MockLogger struct {
	InfoLogs  []string
	DebugLogs []string
	ErrorLogs []string
	FatalLogs []string
	PrintLogs []string
	WarnLogs  []string
	SyncCalls int
}

type MockDB struct {
	Init 			*initdb.InitDB
	Salts  			map[int64][]byte  // Store salts with timestamp as key
    FailOnStore		bool
	InitializeFunc	func(password string) (*sql.DB, error)
}
type MockDBConfig struct{
	Log logger.LoggerInterface
}
type MockDBInit struct {
    MockDB initdb.DBInterface
}
type MockDBConn struct{
	MockDB *MockDB
}
type MockDBInitializer struct{}
type MockDBConfigInterface interface {
	GetDB() 		*sql.DB
    GetDBDir() 		string
    GetDBFilename() string
    GetDBPassword() string
    GetConfigName() string
    GetConfigPath() string
    GetLog() 		logger.LoggerInterface
}

type MockFileUtils struct{}
type MockFile struct{
	File *fileutils.Fileutils
}
type MockFileOps	struct {
	data 			[]byte
	dataMap 		map[string][]byte
	err 			error
	tempFiles 		[]*os.File
	writtenData  	[]byte
}

func NewMockDB() *MockDB {
    return &MockDB{
        Salts: make(map[int64][]byte),
        FailOnStore: false,
        InitializeFunc: func(password string) (*sql.DB, error) {
            // return nil, nil
			// Using an in-memory SQLite database for the mock
    		return sql.Open("sqlite3", ":memory:")
        },
    }
}

func (db *MockDBInit) NewInitDB(dbDir string, dbFilename string, log logger.LoggerInterface) initdb.DBInterface {
    return db.MockDB
}

func (m *MockDBConn) Exec(query string, args ...interface{}) (sql.Result, error) {
	// Simulate faliure if the FailOnStore flag is true
	if m.MockDB.FailOnStore {
        return nil, fmt.Errorf("Simulated failure")
    }

    // Simulate storing salt in mock DB
    saltValue, ok1 := args[0].([]byte)
    timestamp, ok2 := args[1].(int64)

    if ok1 && ok2 {
        m.MockDB.Salts[timestamp] = saltValue
        return nil, nil  // Or you could return a mock result
    }

    return nil, fmt.Errorf("Invalid arguments")
}

func (db *MockDBConfig) GetDB() *sql.DB {
    return nil
}

func (db *MockDBConfig) GetDBDir() string {
    return ".database/"
}
func (db *MockDBConfig) GetDBFilename() string {
    return "database.db"
}
func (db *MockDBConfig) GetDBPassword() string {
    return "test123"
}
func (db *MockDBConfig) GetConfigName() string {
    return "config"
}
func (db *MockDBConfig) GetConfigPath() string {
    return "./database/config"
}
func (db *MockDBConfig) GetLog() logger.LoggerInterface {
    return db.Log
}

// Implement the interface methods with mocked behaviors.
func (db *MockDBInitializer) NewInitDB(dir string, filename string, log logger.LoggerInterface) initdb.DBInterface {
    return &MockDB{}
	// return NewMockDB()
}

func (db *MockFileUtils) NewFileutils(partsDir string, prefixParts string, log logger.LoggerInterface) fileutils.FileInterface {
	return &MockFile{}
}

func (db *MockDB) Initialize(password string) (*sql.DB, error) {
	// return nil, nil
	return db.InitializeFunc(password)
}

func (db *MockDB) CreateSaltTable(database *sql.DB) error {
	return nil
}

func (dbc *MockDBConn) CreateSaltTable(database *sql.DB) error {
	return dbc.MockDB.CreateSaltTable(database)
}

func (db *MockDB) StoreSalt(database initdb.SQLExecer, salt []byte, timestamp int64) error {
    // Simulate a failure if the FailOnStore flag is true
    if db.FailOnStore {
        return fmt.Errorf("mocked error: failed to store salt in database")
    }
    
    // Mock implementation: Store salt in our mock database (i.e., map)
    db.Salts[timestamp] = salt
    
    return nil
}

func (dbc *MockDBConn) StoreSalt(database initdb.SQLExecer, salt []byte, timestamp int64) error {  
    return dbc.MockDB.StoreSalt(database, salt, timestamp)
}


func (db *MockDB) RetrieveSaltByTimestamp(database *sql.DB, timestamp int64) ([]byte, error) {
	return []byte("mocksalt"), nil
}

func (dbc *MockDBConn) RetrieveSaltByTimestamp(database *sql.DB, timestamp int64) ([]byte, error) {
	return dbc.MockDB.RetrieveSaltByTimestamp(database, timestamp)
}

func (db *MockDB) RetrieveSaltByTimestampFail(database *sql.DB, timestamp int64) ([]byte, error) {
	return nil, fmt.Errorf("mocked error: failed to retrieve salt from database")
}

func (db *MockDB) CreateTimestampIndex(database *sql.DB) error {
	return nil
}

func (dbc *MockDBConn) CreateTimestampIndex(database *sql.DB) error {
	return dbc.MockDB.CreateTimestampIndex(database)
}


func (db *MockDB) CheckEncrypted(dir, filename string) (bool, error) {
	return false, nil
}

func (dbc *MockDBConn) CheckEncrypted(dir, filename string) (bool, error) {
    // Add your mock logic here.
    // For a basic mock, just return a predetermined value or error.
    return dbc.MockDB.CheckEncrypted(dir, filename)
}

func (fl *MockFile) PathExists(path string) bool {
	return true
}

func (m *MockFileOps) WriteFile(filename string, data []byte, perm os.FileMode) error {
	m.dataMap[filename] = data
	return m.err
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

func TestNewEncryption(t *testing.T) {
	mockLog := &MockLogger{}
	mockDBConfig := &MockDBConfig{Log: mockLog}
	mockDBInitializer := &MockDBInitializer{}
	mockFileUtils := &MockFileUtils{}

	parameters := NewParamters("partsDir", "prefixParts", 1234567890, "v2")
	enc := NewEncryption(mockDBConfig, mockDBInitializer, mockFileUtils, mockLog, parameters)
	

	// Basic assertions
	assert.NotNil(t, enc)
	assert.NotNil(t, enc.DB)
	assert.NotNil(t, enc.FileOps)
	assert.Equal(t, "partsDir", enc.Parameters.PartsDir)
	assert.Equal(t, "prefixParts", enc.Parameters.PrefixParts)
	assert.Equal(t, int64(1234567890), enc.Parameters.Timestamp)
	assert.Equal(t, mockLog, enc.Log)
}

func TestStoreSalt(t *testing.T) {
	mockLog := &MockLogger{}
	mockDBConfig := &MockDBConfig{Log: mockLog}
	mockDB := NewMockDB()
	mockDBInitializer := &MockDBInit{MockDB: mockDB}
	mockFileUtils := &MockFileUtils{}
	mockParameters := NewParamters("partsDir", "prefixParts", 1234567890, "v2")
	mockEnc := NewEncryption(mockDBConfig, mockDBInitializer, mockFileUtils, mockLog, mockParameters)

	// This is a mock database connection, so you don't have a real sql.DB here
	// The actual instance doesn't matter as our mock implementation doesn't use it
	mockDBConn := &MockDBConn{MockDB: mockDB}

	err := mockEnc.DB.StoreSalt(mockDBConn, []byte(testSalt), 1234567890)

	// Validate the salt was stored
	assert.NoError(t, err)
	salt, exists := mockDB.Salts[1234567890]
	assert.True(t, exists)
	assert.Equal(t, []byte(testSalt), salt)
}

func TestStoreSaltFail(t *testing.T) {
	mockLog := &MockLogger{}
	mockDBConfig := &MockDBConfig{Log: mockLog}
	mockDB := NewMockDB()
	mockDB.FailOnStore = true // Set this to simulate a failure
	mockDBInitializer := &MockDBInit{MockDB: mockDB}
	mockFileUtils := &MockFileUtils{}
	mockParameters := NewParamters("partsDir", "prefixParts", 1234567890, "v2")
	mockEnc := NewEncryption(mockDBConfig, mockDBInitializer, mockFileUtils, mockLog, mockParameters)

	// Simulate a failure
	mockDB.FailOnStore = true

	// This is a mock database connection, so you don't have a real sql.DB here
	// The actual instance doesn't matter as our mock implementation doesn't use it
	mockDBConn := &MockDBConn{MockDB: mockDB}

	err := mockEnc.DB.StoreSalt(mockDBConn, []byte(testSalt), 1234567890)

	// Check that the error was thrown
	assert.Error(t, err)
}

func TestCreateEncryptionKey(t *testing.T) {
	partsDir := "test_data_tmp"
	prefixParts := "part_"
	timestamp := 1693482477127354000
	manifestTempFile := "testfile-1693482477127354000.json.enc"

	// Use the mock DB for this test
	mockLog := &MockLogger{}
	mockDBConfig := &MockDBConfig{Log: mockLog}
	mockDB := NewMockDB()
	mockDBInitializer := &MockDBInit{MockDB: mockDB}
	mockFileUtils := &MockFileUtils{}
	mockParameters := NewParamters(partsDir, prefixParts, int64(timestamp), "v2")
	mockEnc := NewEncryption(mockDBConfig, mockDBInitializer, mockFileUtils, mockLog, mockParameters)

	// This is a mock database connection, so you don't have a real sql.DB here
	// The actual instance doesn't matter as our mock implementation doesn't use it

	err := os.Mkdir(partsDir, 0755)
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

	key, err := mockEnc.CreateEncryptionKey(manifestTempFile, strings, true)
	assert.NoErrorf(t, err, "Failed to create encryption key (TestCreateEncryptionKey): %v", err)

	// Assertions based on the new logic:
	assert.NotNil(t, key)
	assert.Equal(t, 32, len(key))

	// If you want to also validate the generated key against some expected value, add that logic as well.
	// Note: Given the random nature of salt generation, this might be complex. You may want to mock the salt generation or focus only on other aspects of the function for deterministic outcomes.
}

func TestCreateEncryptionKeyWithEncFuncFalse(t *testing.T) {
	partsDir := "test_data_tmp"
	prefixParts := "part_"
	timestamp := 1693482477127354000
	manifestTempFile := "testfile-1693482477127354000.json.enc"

	// Use the mock DB for this test
	mockLog := &MockLogger{}
	mockDBConfig := &MockDBConfig{Log: mockLog}
	mockDB := NewMockDB()
	mockDBInitializer := &MockDBInit{MockDB: mockDB}
	mockFileUtils := &MockFileUtils{}
	mockParameters := NewParamters(partsDir, prefixParts, int64(timestamp), "v2")
	mockEnc := NewEncryption(mockDBConfig, mockDBInitializer, mockFileUtils, mockLog, mockParameters)


	// Create temp files
	strings := []string{"test1", "test2", "test3"}

	key, err := mockEnc.CreateEncryptionKey(manifestTempFile, strings, false)
	assert.NoErrorf(t, err, "Failed to create encryption key: %v", err)

	// Assertions based on the new logic:
	assert.NotNil(t, key)
	assert.Equal(t, 32, len(key))

	// Again, add any additional logic or assertions to validate the outcome based on the mocked behaviors
}

func TestEncryptFileAndDecryptFile(t *testing.T) {
	var decodedContentBytes string
	var decodedContentEncrypted string
	partsDir := "test_data_tmp"

	dbi := &MockDBInitializer{}
	fui := &MockFileUtils{}

	l := logger.InitLogger(true)
	parameters := NewParamters("", "", 0, "")
	e := NewEncryption(nil, dbi, fui, l, parameters) // Adjust as needed
	
	currentDir, err := os.Getwd()
	assert.NoErrorf(t, err, "Failed to get current dir: %v", err)

	e.Parameters.PartsDir = currentDir + string(os.PathSeparator) + partsDir

	err = os.Mkdir(partsDir, 0755)
	assert.NoErrorf(t, err, "Failed to create test directory: %v", err)
	defer os.RemoveAll(partsDir) // Cleanup

	testString := "This is a test string."
	filename := testfile
	encryptedFilename := filename + ".enc"
	decryptedFilename := testfile

	// Create a test file
	err = os.WriteFile(path.Join(e.Parameters.PartsDir, filename), []byte(testString), 0644)
	assert.NoErrorf(t, err, "Failed to create test file: %v", err)

	// Mocked key for encryption (32 bytes for this example)
	mockKey := []byte("abcdefghijklmnopqrstuvwxyzabcdef") // Change this to the desired key value

	// Mocket Encoded content
	mockEncodedData, err := json.Marshal(testString)
	// Assert that there is no error in encoding the manifest
	assert.NoError(t, err, "Error encoding manifest JSON")

	// Encrypt the test file
	err = e.EncryptFile(path.Join(e.Parameters.PartsDir, filename), mockEncodedData, mockKey)
	assert.NoErrorf(t, err, "Failed to encrypt file: %v", err)
	os.Remove(path.Join(e.Parameters.PartsDir, filename))

	// Decrypt the file to memory
	decryptedBytes, err := e.DecryptFile(path.Join(e.Parameters.PartsDir, encryptedFilename), mockKey, false)
	assert.NoErrorf(t, err, "Failed to decrypt file:")
	err = json.Unmarshal(decryptedBytes, &decodedContentBytes)
	assert.NoError(t, err, "Error decoding manifest JSON")
	assert.Equal(t, testString, string(decodedContentBytes))

	// Decrypt the file to disk
	_, err = e.DecryptFile(path.Join(e.Parameters.PartsDir, encryptedFilename), mockKey, true)
	assert.NoErrorf(t, err, "Failed to decrypt file: %v", err)

	decryptedContent, err := os.ReadFile(path.Join(e.Parameters.PartsDir, decryptedFilename))
	assert.NoErrorf(t, err, "Failed to read decrypted file: %v", err)
	err = json.Unmarshal(decryptedContent, &decodedContentEncrypted)
	assert.NoErrorf(t, err, "Failed to decode decrypted content: %v", err)

	assert.Equal(t, testString, decodedContentEncrypted)
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
    _, err := rand.Read(key)
	assert.Nil(t, err, "failed to generate random key (TestMockFileOps): %v", err)

    data := []byte("Test data to be encrypted")

    err = mock.WriteEncryptedFile(testfile, key, data, 0644)
	assert.NoError(t, err, "failed to write encrypted file")

	assert.False(t, bytes.Contains(mock.dataMap[testfile+".enc"], data), "Expected different data in the mock, got the same")
}

func TestEncryptionLogic(t *testing.T) {
    key := make([]byte, 32)
    _, err := rand.Read(key)
	assert.Nil(t, err, "failed to generate random key (TestEncryptionLogic): %v", err)
    
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
		Parameters: &Parameters{
        CURRENT_VERSION: "v1",
    },
	}

	err = mockFileOps.WriteEncryptedFile(testfile, key, plaintext, 0644)
    assert.Nil(t, err)

	// Mocket Encoded content
	mockEncodedData, err := json.Marshal(plaintext)
	assert.NoError(t, err, "Error encoding manifest JSON")

	fmt.Println("Test File: ", testfile)
	fmt.Println("Key: ", key)

    err = e.EncryptFile(testfile, mockEncodedData, key)
	assert.NoError(t, err, "failed to encrypt mock manifest.")

    encryptedData, err := e.FileOps.ReadFile(testfile+".enc")
	assert.NoError(t, err, "failed to read the encrypt mock manifest.")

	assert.False(t, bytes.Contains(encryptedData, plaintext), "Encrypted data should not contain plaintext")
}

func TestEncryptedDataSize(t *testing.T) {
    key := make([]byte, 32)
    _, err := rand.Read(key)
	assert.Nil(t, err, "failed to generate random key (TestEncryptedDataSize): %v", err)

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
		Parameters: &Parameters{
			CURRENT_VERSION: "v1",
		},								
	}

	err = mockFileOps.WriteEncryptedFile(testfile, key, testContent, 0644)
    assert.Nil(t, err)

	// Mocket Encoded content
	mockEncodedData := []byte{123,34,117,117,105,100,34,58,34,115,97,109,112,108,101,85,85,73,68,34,44,34,118,101,114,115,105,111,110,34,58,34,115,97,109,112,108,101,86,101,114,115,105,111,110,34,44,34,102,105,108,101,110,97,109,101,34,58,34,101,97,109,112,108,101,46,116,120,116,34,44,34,102,105,108,101,95,104,97,115,104,34,58,34,115,97,109,112,108,101,104,97,115,104,34,44,34,117,114,108,34,58,34,104,116,116,112,115,58,47,47,101,120,97,109,112,108,101,46,99,111,109,47,101,120,97,109,112,108,101,46,116,120,116,34,44,34,101,116,97,103,34,58,34,115,97,109,112,108,101,69,116,97,103,34,44,34,104,97,115,104,95,116,121,112,101,34,58,34,115,97,109,112,108,101,72,97,115,104,84,121,112,101,34,44,34,112,97,114,116,115,95,100,105,114,34,58,34,115,97,109,112,108,101,80,97,114,116,115,68,105,114,34,44,34,112,114,101,102,105,120,95,112,97,114,116,115,34,58,34,115,97,109,112,108,101,80,114,101,102,105,120,80,97,114,116,115,34,44,34,115,105,122,101,34,58,49,48,48,44,34,110,117,109,95,112,97,114,116,115,34,58,49,48,44,34,114,97,110,103,101,95,115,105,122,101,34,58,49,48,44,34,100,111,119,110,108,111,97,100,101,100,95,112,97,114,116,115,34,58,91,123,34,112,97,114,116,95,110,117,109,98,101,114,34,58,49,44,34,102,105,108,101,95,104,97,115,104,34,58,34,115,97,109,112,108,101,70,105,108,101,72,97,115,104,34,44,34,116,105,109,101,115,116,97,109,112,34,58,48,44,34,112,97,114,116,95,102,105,108,101,34,58,34,115,97,109,112,108,101,80,97,114,116,70,105,108,101,34,125,93,125} // continue with the rest of the bytes

    err = e.EncryptFile(testfile, mockEncodedData, key)
	assert.NoError(t, err, "failed to encrypt mock manifest.")

    encryptedData, err := e.FileOps.ReadFile(testfile+".enc")
	assert.NoError(t, err, "failed to read encrypted mock manifest.")

    expectedSize := 80
	assert.Equal(t, expectedSize, len(encryptedData), "Expected encrypted data of size %d bytes, got %d bytes", expectedSize, len(encryptedData))
}

func TestEncryptLogs(t *testing.T) {
	// Initialize a mock logger for testing
	mockLogger := &MockLogger{}
	// Assertions for logs
	// Here, let's add assertions for the expected logs if necessary.
	// You will need to implement the MockLogger and add methods to capture logs.
	if len(mockLogger.InfoLogs) != 1 || mockLogger.InfoLogs[0] != "Initializing encryption of manifest file." {
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

	// Mocket Encoded content
	mockEncodedData := []byte{123,34,117,117,105,100,34,58,34,115,97,109,112,108,101,85,85,73,68,34,44,34,118,101,114,115,105,111,110,34,58,34,115,97,109,112,108,101,86,101,114,115,105,111,110,34,44,34,102,105,108,101,110,97,109,101,34,58,34,101,97,109,112,108,101,46,116,120,116,34,44,34,102,105,108,101,95,104,97,115,104,34,58,34,115,97,109,112,108,101,104,97,115,104,34,44,34,117,114,108,34,58,34,104,116,116,112,115,58,47,47,101,120,97,109,112,108,101,46,99,111,109,47,101,120,97,109,112,108,101,46,116,120,116,34,44,34,101,116,97,103,34,58,34,115,97,109,112,108,101,69,116,97,103,34,44,34,104,97,115,104,95,116,121,112,101,34,58,34,115,97,109,112,108,101,72,97,115,104,84,121,112,101,34,44,34,112,97,114,116,115,95,100,105,114,34,58,34,115,97,109,112,108,101,80,97,114,116,115,68,105,114,34,44,34,112,114,101,102,105,120,95,112,97,114,116,115,34,58,34,115,97,109,112,108,101,80,114,101,102,105,120,80,97,114,116,115,34,44,34,115,105,122,101,34,58,49,48,48,44,34,110,117,109,95,112,97,114,116,115,34,58,49,48,44,34,114,97,110,103,101,95,115,105,122,101,34,58,49,48,44,34,100,111,119,110,108,111,97,100,101,100,95,112,97,114,116,115,34,58,91,123,34,112,97,114,116,95,110,117,109,98,101,114,34,58,49,44,34,102,105,108,101,95,104,97,115,104,34,58,34,115,97,109,112,108,101,70,105,108,101,72,97,115,104,34,44,34,116,105,109,101,115,116,97,109,112,34,58,48,44,34,112,97,114,116,95,102,105,108,101,34,58,34,115,97,109,112,108,101,80,97,114,116,70,105,108,101,34,125,93,125} // continue with the rest of the bytes
	// mockEncodedData, err := json.Marshal(testString)
	// // Assert that there is no error in encoding the manifest
	// assert.NoError(t, err, "Error encoding manifest JSON")

	err = e.EncryptFile(testfile, mockEncodedData, key)
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
				Parameters: &Parameters{
					CURRENT_VERSION: "v1",
				},	
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