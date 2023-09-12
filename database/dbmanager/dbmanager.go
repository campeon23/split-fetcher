// File: dbmanager.go
package dbmanager

import (
	"database/sql"

	"github.com/campeon23/split-fetcher/database/initdb"
	"github.com/campeon23/split-fetcher/logger"
)

type DatabaseManager struct {
	initDB *initdb.InitDB
}

func NewDatabaseManager(DBDir string, DBFilename string, log logger.LoggerInterface) *DatabaseManager {
	return &DatabaseManager{initDB: initdb.NewInitDB(DBDir, DBFilename, log)}
}

func (dm *DatabaseManager) OpenEncryptedDatabase(password string) (*sql.DB, error) {
	return dm.initDB.InitializeDB(password)
}

func (dm *DatabaseManager) InsertData(db *sql.DB, query string, args ...interface{}) (sql.Result, error) {
	return db.Exec(query, args...)
}

func (dm *DatabaseManager) RetrieveData(db *sql.DB, query string, args ...interface{}) (*sql.Rows, error) {
	return db.Query(query, args...)
}
