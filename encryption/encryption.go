package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/campeon23/multi-source-downloader/fileutils"
	"github.com/campeon23/multi-source-downloader/logger"
	"golang.org/x/crypto/pbkdf2"
)

type Encryption struct {
	PartsDir		string
	PrefixParts		string
	Log				logger.LoggerInterface
	FileOps 		FileOperator
	GetWrittenData 	[]byte
}

type FileOperator interface {
    Remove(name string) 	error
    Create(name string) 	(*os.File, error)
	ReadFile(name string)	([]byte, error)
	Open(name string)		(*os.File, error)
	WriteFile(filename string, data []byte, perm os.FileMode) error
    WriteEncryptedFile(filename string, data []byte, key []byte, perm os.FileMode) error
}

type RealFileOps struct{
	Enc *Encryption
}

func NewEncryption(partsDir string, prefixParts string,log logger.LoggerInterface) *Encryption {
	enc := &Encryption{
		PartsDir: partsDir,
		PrefixParts: prefixParts,
		Log: log,
		// FileOps: &RealFileOps{},
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

	// encryptedData, err := EncryptFile(data, key)
	// if err != nil {
	// 	return err
	// }

	// return os.WriteFile(filename, encryptedData, perm)

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

func (e *Encryption) CreateEncryptionKey(strings []string) ([]byte, error) {
	f := fileutils.NewFileutils(e.PartsDir, e.PrefixParts, e.Log)
	// Sort the strings in reverse order
	sort.Sort(sort.Reverse(sort.StringSlice(strings)))

	// Concatenate the sorted strings
	var buffer bytes.Buffer
	for _, str := range strings {
		buffer.WriteString(str)
	}

	hashStr, err := f.CombinedMD5HashForPrefixedFiles(e.PartsDir, e.PrefixParts)
	if err != nil {
		return nil, err
	}

	// Use the concatenated string with PBKDF2 to derive a key
	salt := []byte(hashStr) // Use a constant or random salt as needed

	key := pbkdf2.Key([]byte(buffer.Bytes()), salt, 4096, 32, sha256.New) // Pass the buffer as a byte slice

	return key, nil
}

// encryptFile encrypts the file with the given key and writes the encrypted data to a new file
func (e *Encryption) EncryptFile(filename string, key []byte) error {
	e.Log.Infow("Initializing ecryption of manifest file.")
	plaintext, err := e.FileOps.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)

	paddingLength := aes.BlockSize - len(plaintext)%aes.BlockSize
	padding := make([]byte, paddingLength)
	for i := range padding {
		padding[i] = byte(paddingLength)
	}
	plaintext = append(plaintext, padding...)

	ciphertext := make([]byte, len(plaintext))
	encrypter.CryptBlocks(ciphertext, plaintext)

	// Generate HMAC of the ciphertext
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	encryptedFilename := filename + ".enc"
	encryptedFile, err := e.FileOps.Create(encryptedFilename)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	_, err = encryptedFile.Write(iv)
	if err != nil {
		return fmt.Errorf("failed to create aes block size: %v", err)
	}
	_, err = encryptedFile.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to create ciphertext: %v", err)
	}

	// Write HMAC to file
	_, err = encryptedFile.Write(mac)
	if err != nil {
		return fmt.Errorf("failed to write HMAC: %w", err)
	}

	e.Log.Debugw("File encrypted successfully and saved as:", 
		"encryptedFilename", encryptedFilename,
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

	iv := make([]byte, aes.BlockSize)
	_, err = encryptedFile.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to read aes block size: %w", err)
	}

	ciphertext, err := io.ReadAll(encryptedFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Extract HMAC from the end of the ciphertext and remove it
	mac := ciphertext[len(ciphertext)-32:]
	ciphertext = ciphertext[:len(ciphertext)-32]

	// Validate HMAC
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	expectedMac := h.Sum(nil)
	if !hmac.Equal(mac, expectedMac) {
		return nil, fmt.Errorf("integrity check failed: HMAC mismatch")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher: %w", err)
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	paddingLength := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-paddingLength]

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