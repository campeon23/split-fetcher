package initdb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	sqlite3 "github.com/mutecomm/go-sqlcipher/v4" // SQLite driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock logger to satisfy interface
type MockLogger struct {
	InfoLogs  []string
	DebugLogs []string
	ErrorLogs []string
	FatalLogs []string
	PrintLogs []string
	WarnLogs  []string
	SyncCalls int
}

type MockResult struct{}

func (r MockResult) LastInsertId() (int64, error) { return 0, nil }
func (r MockResult) RowsAffected() (int64, error) { return 0, nil }

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

// Mocked versions of dependencies
type MockedDB struct {
	mock.Mock
}

func (m *MockedDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	argsRet := m.Called(query, args)
	return argsRet.Get(0).(sql.Result), argsRet.Error(1)
}

// setUpDB sets up an in-memory SQLite database for testing.
func setUpDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	assert.NoError(t, err, "Failed to open database: %v", err)
	return db
}

func TestCreateSaltTable(t *testing.T) {
	db := setUpDB(t)
	defer db.Close()

	i := &InitDB{}

	err := i.CreateSaltTable(db)
	assert.NoError(t, err, "Failed to create salt table (TestCreateSaltTable): %v", err)
}

func TestStoreSalt(t *testing.T) {
	db := setUpDB(t)
	defer db.Close()

	i := &InitDB{}
	err := i.CreateSaltTable(db)
	assert.NoError(t, err, "Failed to create salt table (TestStoreSalt): %v", err)

	saltValue := []byte("testSalt")
	_, err = i.StoreSalt(db, saltValue, 1234567890)
	assert.NoError(t, err, "Failed to store salt (TestStoreSalt): %v", err)
}

func TestRetrieveSalt(t *testing.T) {
	db := setUpDB(t)
	defer db.Close()

	i := &InitDB{}
	err := i.CreateSaltTable(db)
	assert.NoError(t, err, "Failed to create salt table (TestRetrieveSalt): %v", err)

	saltValue := []byte("testSalt")
	id, err := i.StoreSalt(db, saltValue, 1234567890)
	assert.NoError(t, err, "Failed to store salt: %v", err)

	retrievedSalt, err := i.RetrieveSalt(db, id)
	assert.NoError(t, err, "Failed to retrieve salt: %v", err)
	assert.Equal(t, string(saltValue), string(retrievedSalt), "Retrieved salt does not match stored salt")
}

func TestRetrieveSaltByTimestamp(t *testing.T) {
	db := setUpDB(t)
	defer db.Close()

	i := &InitDB{}
	err := i.CreateSaltTable(db)
	assert.NoError(t, err, "Failed to create salt table (TestRetrieveSaltByTimestamp): %v", err)

	saltValue := []byte("testSalt")
	_, err = i.StoreSalt(db, saltValue, 1234567890)
	assert.NoError(t, err, "Failed to store salt: %v", err)

	retrievedSalt, err := i.RetrieveSaltByTimestamp(db, 1234567890)
	assert.NoError(t, err, "Failed to retrieve salt by timestamp: %v", err)
	assert.Equal(t, string(retrievedSalt), string(saltValue), "Retrieved salt does not match stored salt")
}

func TestCreateTimestampIndex(t *testing.T) {
	db := setUpDB(t)
	defer db.Close()

	i := &InitDB{}
	err := i.CreateSaltTable(db)
	assert.NoError(t, err, "Failed to create salt table: %v", err)

	err = i.CreateTimestampIndex(db)
	assert.NoError(t, err, "Failed to create timestamp index: %v", err)
}

var sqlite3IsEncrypted = func(filepath string) (bool, error) {
	return sqlite3.IsEncrypted(filepath)
}

func TestSQLite3TempDB(t *testing.T) {
	// Create a temporary file for the test database
	tempDBFile, err := os.CreateTemp("", "testDB-*.db")
	assert.NoError(t, err, "Failed to create temp DB file: %v", err)
	defer os.Remove(tempDBFile.Name()) // Remove temporary file after use

	// Initialize SQLite3 database
	db, err := sql.Open("sqlite3", tempDBFile.Name())
	assert.NoError(t, err, "Failed to open the database: %v", err)
	defer db.Close()

	// Use the database for your tests

	// Create a table
	_, err = db.Exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
	assert.NoError(t, err, "Failed to create table: %v", err)

	// Insert a value
	_, err = db.Exec("INSERT INTO test (name) VALUES (?)", "testName")
	assert.NoError(t, err, "Failed to insert value: %v", err)

	// Query and check
	rows, err := db.Query("SELECT name FROM test")
	assert.NoError(t, err, "Failed to query: %v", err)
	defer rows.Close()

	for rows.Next() {
		var name string
		assert.NoError(t, rows.Scan(&name), "Failed to scan row: %v", err)
		assert.Equal(t, name, "testName", "Unexpected name: %v", name)
	}
}

func TestCheckEncrypted(t *testing.T) {
	i := &InitDB{}
	// Assuming the Logger interface has Debugf function. This would be a mock
	i.Log = &MockLogger{}

	// Create a temporary file for the test database
	tempDBFile, err := os.CreateTemp("../", "testDB-*.db")
	assert.NoError(t, err, "Failed to create temp DB file: %v", err)
	defer os.Remove(tempDBFile.Name()) // Remove temporary file after use

	// Initialize SQLite3 database
	db, err := sql.Open("sqlite3", tempDBFile.Name())
	assert.NoError(t, err, "Failed to open the database: %v", err)
	defer db.Close()

	// Use the database for your tests

	// Create a table
	_, err = db.Exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
	assert.NoError(t, err, "Failed to create table: %v", err)

	// Insert a value
	_, err = db.Exec("INSERT INTO test (name) VALUES (?)", "testName")
	assert.NoError(t, err, "Failed to insert value: %v", err)

	// Query and check
	rows, err := db.Query("SELECT name FROM test")
	assert.NoError(t, err, "Failed to query: %v", err )
	defer rows.Close()

	for rows.Next() {
		var name string
		assert.NoError(t, rows.Scan(&name), "Failed to scan row: %v", err)
		assert.Equal(t, name, "testName", "Unexpected name: %v", name)
	}

	tempDir := filepath.Dir(tempDBFile.Name())            // Get the directory from the path
	tempFilename := filepath.Base(tempDBFile.Name())      // Get the filename from the path

	// Save the original function
	originalIsEncrypted := sqlite3IsEncrypted

	// Mock the function
	sqlite3IsEncrypted = func(dbPath string) (bool, error) {
		return false, nil  // or whatever value/error you want to test
	}

	// Ensure the original function is restored at the end of the test
	defer func() { sqlite3IsEncrypted = originalIsEncrypted }()

	_, err = i.CheckEncrypted(tempDir, tempFilename)
	assert.NoError(t, err, "Failed to check if database is encrypted: %v", err)
}

func TestInitializeDB(t *testing.T) {
	logger := new(MockLogger)
	// logger.On("Debugw", "Initializing encrypted database.").Return()

	initDB := NewInitDB("testDir", "testFile", logger)

	// Assuming fileutils.NewFileutils is modified to accept interfaces for easier mocking.
	// The path check and directory creation is not tested here.
	// You may need to modify the function to support such mocking.

	db, err := initDB.InitializeDB("testPassword")
	assert.NoError(t, err)
	assert.NotNil(t, db)
}

func TestInitDBStoreSalt(t *testing.T) {
	dbMock := new(MockedDB)
	// dbMock.On("Exec", mock.Anything, mock.Anything).Return(nil, nil)
	dbMock.On("Exec", mock.Anything, mock.Anything).Return(MockResult{}, nil)

	initDB := &InitDB{}

	_, err := initDB.StoreSalt(dbMock, []byte("testSalt"), 123456)
	assert.NoError(t, err)
}

func TestInitDBRetrieveSaltByTimestamp(t *testing.T) {
	// This test can be extended with proper mocks for sql.DB and QueryRow method.
	// For now, just a placeholder to demonstrate.
}