package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/campeon23/multi-source-downloader/database/initdb"
	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/logger"
	"github.com/campeon23/multi-source-downloader/utils"
	"golang.org/x/crypto/argon2"
)

type Encryption struct {
	DB 				initdb.DBInterface
	FI 				fileutils.FileInterface
	DBConfig 		initdb.DBConfigInterface
	PartsDir		string
	PrefixParts		string
	Timestamp		int64
	Log				logger.LoggerInterface
	FileOps 		fileutils.FileOperator
	GetWrittenData 	[]byte
	DBInitializer 	initdb.DBInitializer
    FUInitializer  	fileutils.FUInitializer
}

type RealFileOps struct{
	Enc *Encryption
}

func NewEncryption(dbcfg initdb.DBConfigInterface, dbInitializer initdb.DBInitializer, fuInitializer fileutils.FUInitializer, partsDir string, prefixParts string, timestamp int64, log logger.LoggerInterface) *Encryption {
	enc := &Encryption{
		DB: &initdb.RealDB{},
		DBConfig: dbcfg,
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Timestamp: timestamp,
		DBInitializer: dbInitializer,
		FUInitializer: fuInitializer,
		Log: log,
	}
	enc.FileOps = &RealFileOps{Enc: enc}
    return enc
}

func (e *Encryption) SetLogger(log logger.LoggerInterface) {
    e.Log = log
}

func (r *RealFileOps) Remove(name string) error {
    return os.Remove(name)
}

func (r *RealFileOps) Create(name string) (*os.File, error) {
    return os.Create(name)
}

func (r *RealFileOps) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (r *RealFileOps) Open(name string) (*os.File, error) {
	return os.Open(name)
}

func (r *RealFileOps) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

func (r *RealFileOps) WriteEncryptedFile(filename string, data []byte, key []byte, perm os.FileMode) error {
	if len(key) != 32 {  // Check key length for AES-256
		return errors.New("key length must be 32 bytes for AES-256")
	}

	// Since EncryptFile uses the filename to read the file, 
    // first write the data to the file and then call EncryptFile.
	err := r.WriteFile(filename, data, perm)
	if err != nil {
		return err
	}

	err = r.Enc.EncryptFile(filename, key)
	if err != nil {
		return err
	}

	return nil
}

func (r *RealFileOps) WriteDecryptedFile(filename string, key []byte, data []byte, perm os.FileMode) error {
	// Decrypt data in memory
	decryptedData, err := r.Enc.DecryptFile(filename, key, false)
	if err != nil {
		return err
	}

	// Write decrypted data to file
	return os.WriteFile(filename, decryptedData, 0644)
}

// Generate a salt value
func generateRandomSalt(length int) ([]byte, error) {
    results := make([]byte, length)
    for i := 0; i < length; i++ {
        salt, err := rand.Int(rand.Reader, big.NewInt(255))
        if err != nil {
            return nil, err
        }
        results[i] = byte(salt.Int64())
    }
    return results, nil
}

func (e *Encryption) CreateEncryptionKey(encryptedFilename string, strings []string, encFunc bool) ([]byte, error) {
	var salt []byte
	var buffer bytes.Buffer
	
	i := e.DBInitializer.NewInitDB(e.DBConfig.GetDBDir(), e.DBConfig.GetDBFilename(), e.DBConfig.GetLog())
	f := e.FUInitializer.NewFileutils(e.PartsDir, e.PrefixParts, e.Log)
	u := utils.NewUtils(e.PartsDir, e.Log)

	e.Log.Debugw("Initializing encryption key generation.")

	// Initialize the encrypted database
	db, err := i.Initialize(e.DBConfig.GetDBPassword())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Sort the strings in reverse order
	sort.Sort(sort.Reverse(sort.StringSlice(strings)))

	// Concatenate the sorted strings
	for _, str := range strings {
		buffer.WriteString(str)
	}

	if encFunc {
		salt, err = generateRandomSalt(128 / 8)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random salt: %w", err)
		}
		// i.CheckEncrypted(e.DBConfig.DBDir, e.DBConfig.DBFilename)
		err := i.StoreSalt(db, salt, e.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to store salt: %w", err)
		}
	} else {
		if f.PathExists(encryptedFilename) { 
			e.Log.Debugw("Encrypted file exists. Retrieving salt from database.")
		} else {
			return nil, fmt.Errorf("failed to find encrypted file: %s", encryptedFilename)
		}

		timeStamp, err := u.ExtractTimestampFromFilename(encryptedFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to extract timestamp from filename: %w", err)
		}

		salt, err = i.RetrieveSaltByTimestamp(db, timeStamp)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve salt by timestamp: %w", err)
		}
	}

	// key := pbkdf2.Key([]byte(buffer.Bytes()), salt, 4096, 32, sha256.New) // Pass the buffer as a byte slice
	key := argon2.IDKey([]byte(buffer.Bytes()), salt, 8, 128*1024, 4, 32)
	e.Log.Debugw("Encryption key generated successfully.")
	return key, nil
}

// encryptFile encrypts the file with the given key and writes the encrypted data to a new file
func (e *Encryption) EncryptFile(filename string, key []byte) error {
	e.Log.Infow("Initializing encryption of manifest file.")
	

	plaintext, err := e.FileOps.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create new cipher: %w", err)
	}

	// GMC encryption mode with random nonce and authentication tag (MAC)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to initialize GCM: %w", err)
	}

	// Generate nonce and encrypt the data with it and the key
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Create ciphertext with nonce prepended to it and append MAC to it as well
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	encryptedFilename := filename + ".enc"
	encryptedFile, err := e.FileOps.Create(encryptedFilename)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %w", err)
	}
	defer encryptedFile.Close()

	_, err = encryptedFile.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	e.Log.Debugw("File encrypted successfully and saved as:", 
		"encryptedFilename", filepath.Base(encryptedFilename),
	)

	err = e.FileOps.Remove(filename)
	if err != nil {
		return fmt.Errorf("cannot remove manifest: %w", err)
	}

	return nil
}

func (e *Encryption) DecryptFile(encryptedFilename string, key []byte, toDisk bool) ([]byte, error) {
	encryptedFile, err := e.FileOps.Open(encryptedFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer encryptedFile.Close()

	ciphertext, err := io.ReadAll(encryptedFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %w", err)
	}

	// Extract nonce and decrypt the data with it and the key
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	if toDisk {
		decryptedFilename := strings.TrimSuffix(encryptedFilename, ".enc")
		decryptedFile, err := e.FileOps.Create(decryptedFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to create decrypted file: %w", err)
		}
		defer decryptedFile.Close()

		_, err = decryptedFile.Write(plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to write decrypted file: %w", err)
		}

		e.Log.Debugw("File decrypted successfully and saved as:",
			"decryptedFilename", decryptedFilename,
		)

		return nil, nil

	} else {
		return plaintext, nil
	}
}