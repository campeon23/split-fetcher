package initdb

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/campeon23/split-fetcher/config"
	"github.com/campeon23/split-fetcher/fileutils"
	"github.com/campeon23/split-fetcher/logger"

	sqlite3 "github.com/mutecomm/go-sqlcipher/v4"
)

type InitDB struct {
	DBDir		string
	DBFilename	string
	Log 		logger.LoggerInterface
}

type DBInitializer interface {
    NewInitDB(dbDir string, dbFilename string, log logger.LoggerInterface) DBInterface
}

type DBInterface interface {
    Initialize(password string) (*sql.DB, error)
	CreateSaltTable(db *sql.DB) error
	StoreSalt(db SQLExecer, salt []byte, timestamp int64) error
    RetrieveSaltByTimestamp(db *sql.DB, timestamp int64) ([]byte, error)
	CreateTimestampIndex(db *sql.DB) error
	CheckEncrypted(dbDir string, dbFilename string) (bool, error)
}

type DBConfigInterface interface {
	GetDB() 		*sql.DB
    GetDBDir() 		string
    GetDBFilename() string
    GetDBPassword() string
	GetConfigName() string
	GetConfigPath() string
	GetLog() 		logger.LoggerInterface
}

type DBInitImpl struct {
    // Any additional fields that you might want to include
}

func NewInitDB(DBDir string, DBFilename string, log logger.LoggerInterface) *InitDB {
	return &InitDB{
		DBDir: 		DBDir,
		DBFilename: DBFilename,
		Log: 		log,
	}
}

// NewInitDB creates a new DB instance based on the provided parameters
func (db *DBInitImpl) NewInitDB(dbDir string, dbFilename string, log logger.LoggerInterface) DBInterface {    
    return &RealDB{
        Init: &InitDB{
            // Necessary fields to initialize your RealDB and its embedded InitDB
            DBDir: dbDir,
			DBFilename: dbFilename,
			Log: log,
        },
    }
}

type RealDB struct {
	Init *InitDB
}

type RealDBConfig struct{
	Config *config.DBConfig
}

type SQLExecer interface {
    Exec(query string, args ...interface{}) (sql.Result, error)
}

// Initialize maps to InitDB's Initialize
func (db *RealDB) Initialize(password string) (*sql.DB, error) {
	return db.Init.InitializeDB(password)
}

func (db *RealDB) CreateSaltTable(database *sql.DB) error {
	return db.Init.CreateSaltTable(database)
}

// StoreSalt maps to InitDB's StoreSalt
func (db *RealDB) StoreSalt(database SQLExecer, salt []byte, timestamp int64) error {
	_, err := db.Init.StoreSalt(database, salt, timestamp)
	if err != nil {
		return fmt.Errorf("failed to store salt in database: %w", err)
	}
	return nil
}

// RetrieveSaltByTimestamp maps to InitDB's RetrieveSaltByTimestamp
func (db *RealDB) RetrieveSaltByTimestamp(database *sql.DB, timestamp int64) ([]byte, error) {
	return db.Init.RetrieveSaltByTimestamp(database, timestamp)
}

func (db *RealDB) CreateTimestampIndex(database *sql.DB) error {
	return db.Init.CreateTimestampIndex(database)
}

func (db *RealDB) CheckEncrypted(dbDir, dbFilename string) (bool, error) {
	return db.Init.CheckEncrypted(dbDir, dbFilename)
}

func (db *RealDBConfig) GetDB() *sql.DB {
	return db.Config.DB
}

func (db *RealDBConfig) GetDBDir() string {
    return db.Config.DBDir
}

func (db *RealDBConfig) GetDBFilename() string {
    return db.Config.DBFilename
}

func (db *RealDBConfig) GetDBPassword() string {
    return db.Config.DBPassword
}

func (db *RealDBConfig) GetConfigName() string {
    return db.Config.ConfigName
}

func (db *RealDBConfig) GetConfigPath() string {
    return db.Config.ConfigPath
}

func (db *RealDBConfig) GetLog() logger.LoggerInterface {
    return db.Config.Log
}

// Initialize initializes the encrypted SQLite database.
func (i *InitDB) InitializeDB(password string) (*sql.DB, error) {
	i.Log.Debugw("Initializing encrypted database.")
	f := fileutils.NewFileutils("", "", i.Log)

	//Ensure the database directory exists
	if !f.PathExists(i.DBDir) {
		if err := os.MkdirAll(i.DBDir, os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}
	// if err := f.ValidateCreatePath(i.DBDir); err != nil {
	// 	return nil, fmt.Errorf("failed to create database directory: %w", err)
	// }

	dbPath := filepath.Join(i.DBDir, i.DBFilename)

	dbPathWithDSN := dbPath + 
		fmt.Sprintf("?_pragma_key=%s" +
					"&_pragma_cipher=aes256cbc" +
					"&_pragma_cipher_page_size=4096" +
					"&_pragma_kdf_iter=256000" +
					"&_pragma_cipher_hmac_algorithm=HMAC_SHA512" +
					"&_pragma_cipher_kdf_algorithm=PBKDF2_HMAC_SHA512",
					url.QueryEscape(password),
		)

	db, err := sql.Open("sqlite3", dbPathWithDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// CreateSaltTable creates a table to store salts in the database.
func (i *InitDB) CreateSaltTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS salts (
		id INTEGER PRIMARY KEY,
		value BLOB NOT NULL UNIQUE,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("failed to create salts table: %w", err)
	}
	return nil

}

// StoreSalt inserts a salt value and its timestamp into the salts table.
// The timestamp is generated when this function is called.

func (i *InitDB) StoreSalt(db SQLExecer, saltValue []byte, manisfestGenerationTimestamp int64) (int64, error) {
	// Insert the salt value and its timestamp into the salts table
    result, err := db.Exec("INSERT INTO salts (value, timestamp) VALUES (?, ?)", saltValue, manisfestGenerationTimestamp)
    if err != nil {
        return 0, fmt.Errorf("failed to insert salt into database: %w", err)
    }

	if result == nil {
        return 0, nil
    }
    
    // Return the ID of the last inserted row. This could be useful if you want to track the insertion.
    return result.LastInsertId()
}

// RetrieveSalt fetches a salt by its ID.
func (i *InitDB) RetrieveSalt(db *sql.DB, id int64) ([]byte, error) {
	var salt []byte
	if err := db.QueryRow("SELECT value FROM salts WHERE id = ?", id).Scan(&salt); err != nil {
		return nil, fmt.Errorf("failed to retrieve salt from database: %w", err)
	}
	return salt, nil
}

// RetrieveSaltByTimestamp fetches a salt by its associated timestamp.
func (i *InitDB) RetrieveSaltByTimestamp(db *sql.DB, timestamp int64) ([]byte, error) {
	var salt []byte
	if err := db.QueryRow("SELECT value FROM salts WHERE timestamp = ?", timestamp).Scan(&salt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no salt found for the given timestamp: %w", err)
		}
		return nil, fmt.Errorf("failed to retrieve salt from database: %w", err)
	}
	return salt, nil
}

// CreateTimestampIndex creates an index on the timestamp column to speed up queries.
func (i *InitDB) CreateTimestampIndex(db *sql.DB) error {
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_timestamp ON salts (timestamp)`)
	if err != nil {
		return fmt.Errorf("failed to create timestamp index: %w", err)
	}
	return nil
}

func (i *InitDB) CheckEncrypted(dbDir string, dbName string) (bool, error) {
	// Check if database is encrypted
	f := fileutils.NewFileutils("", "", i.Log)
	if f.PathExists(filepath.Join(dbDir, dbName)){
		encrypted, err := sqlite3.IsEncrypted(filepath.Join(dbDir, dbName))
		if err != nil {
			return false, fmt.Errorf("failed to check if database is encrypted: %w", err)
		}

		if encrypted {
			i.Log.Debugf("DB is encrypted")
			return true, nil
		} else {
			i.Log.Debugf("DB is unencrypted")
			return false, nil
		}

	} else {
		fmt.Printf("DB does not exist: %v", filepath.Join(dbDir, dbName))
		return false, nil
	}
}