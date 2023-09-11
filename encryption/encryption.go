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
	Log				logger.LoggerInterface
	Parameters 		*Parameters
	FileOps 		fileutils.FileOperator
	GetWrittenData 	[]byte
	DBInitializer 	initdb.DBInitializer
    FUInitializer  	fileutils.FUInitializer
}

type Parameters struct {
	PartsDir		string
	PrefixParts		string
	Timestamp		int64
	CURRENT_VERSION string
}

type RealFileOps struct{
	Enc *Encryption
}

func NewEncryption(dbcfg initdb.DBConfigInterface, dbInitializer initdb.DBInitializer, fuInitializer fileutils.FUInitializer, log logger.LoggerInterface, parameters *Parameters) *Encryption {
	enc := &Encryption{
		DB: &initdb.RealDB{},
		DBConfig: dbcfg,
		Parameters: parameters,
		DBInitializer: dbInitializer,
		FUInitializer: fuInitializer,
		Log: log,
	}
	enc.FileOps = &RealFileOps{Enc: enc}
    return enc
}

func NewParamters(partsDir string, prefixParts string, timestamp int64, currentVersion string) *Parameters {
	return &Parameters{
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Timestamp: timestamp,
		CURRENT_VERSION: currentVersion,
	}
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
	e := NewEncryption(nil, nil, nil, nil, nil)
	// Check key length for AES-256 (32 bytes)
	if len(key) != 32 {  // Check key length for AES-256
		return errors.New("key length must be 32 bytes for AES-256")
	}

	contentData, err := e.FileOps.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Enhancing security by encrypting the data in memory first and 
	// subsequently write the encrypted data directly to the disk. 
	// This process minimizes the risk of exposing plaintext content.
	err = r.Enc.EncryptFile(filename, contentData, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
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

/* Key Generation Logic */
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
	f := e.FUInitializer.NewFileutils(e.Parameters.PartsDir, e.Parameters.PrefixParts, e.Log)
	u := utils.NewUtils(e.Parameters.PartsDir, e.Log)

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

		err := i.StoreSalt(db, salt, e.Parameters.Timestamp)
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

	key := argon2.IDKey([]byte(buffer.Bytes()), salt, 8, 128*1024, 4, 32) // Pass the buffer as a byte slice
	e.Log.Debugw("Encryption key generated successfully.")
	return key, nil
}

/* Encryption Logic */
// encryptFile encrypts the file with the given key and writes the encrypted data to a new file
func (e *Encryption) EncryptFile(filename string, contentData []byte, key []byte) error {
	e.Log.Infow("Initializing encryption of manifest file.")

	// Create ciphertext with nonce prepended to it and append MAC to it as well
	ciphertext, err := e.versionedEncrypt(key, contentData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

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

	return nil
}
 
func (e *Encryption) encryptData(key []byte, contentData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher: %w", err)
	}

	// GMC encryption mode with random nonce and authentication tag (MAC)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM: %w", err)
	}

	// Generate nonce and encrypt the data with it and the key
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}

	// Create ciphertext with nonce prepended to it and append MAC to it as well
	ciphertext := gcm.Seal(nonce, nonce, contentData, nil)

	return ciphertext, nil
}

func (e *Encryption) versionedEncrypt(data []byte, key []byte) ([]byte, error) {
    encryptedData, err := e.encryptData(data, key)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt data: %w", err)
    }
	// Prepend version info to encrypted data
    versionedData := append([]byte(e.Parameters.CURRENT_VERSION), encryptedData...)
    return versionedData, nil
}

/* Decryption Logic */
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

	plaintext, err := e.versionedDecrypt(ciphertext, key)
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

func (e *Encryption) decryptData(ciphertext []byte, key []byte) ([]byte, error) {
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
	return plaintext, nil
}

func (e *Encryption) versionedDecrypt(data []byte, key []byte) ([]byte, error) {
    // Check if data is empty or doesn't even contain version info
    if len(data) <= len(e.Parameters.CURRENT_VERSION) {
        return nil, fmt.Errorf("data is too short to contain version information")
    }

    // Extract version and encrypted data
    version := string(data[:len(e.Parameters.CURRENT_VERSION)])
    encryptedData := data[len(e.Parameters.CURRENT_VERSION):]

    switch version {
    case e.Parameters.CURRENT_VERSION:
        return e.decryptData(encryptedData, key)
    // You can add more cases if you have more versions in the future
    // case "V2":
    //     return e.decryptV2(encryptedData, key)
    default:
        return nil, fmt.Errorf("unsupported encryption version: %s", version)
    }
}
