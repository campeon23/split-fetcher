package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func createEncryptionKey(strings []string) ([]byte, error) {
	// Sort the strings in reverse order
	sort.Sort(sort.Reverse(sort.StringSlice(strings)))

	// Concatenate the sorted strings
	var buffer bytes.Buffer
	for _, str := range strings {
		buffer.WriteString(str)
	}

	// Use the concatenated string with PBKDF2 to derive a key
	salt := []byte("your-salt") // Use a constant or random salt as needed
	key := pbkdf2.Key([]byte(buffer.Bytes()), salt, 4096, 32, sha256.New) // Pass the buffer as a byte slice

	return key, nil
}

// encryptFile encrypts the file with the given key and writes the encrypted data to a new file
func encryptFile(filename string, key []byte) error {
	log.Info("Initializing ecryption of manifest file.")
	plaintext, err := os.ReadFile(filename)
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

	encryptedFilename := filename + ".enc"
	encryptedFile, err := os.Create(encryptedFilename)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	encryptedFile.Write(iv)
	encryptedFile.Write(ciphertext)

	log.Debugw("File encrypted successfully and saved as:", 
		"encryptedFilename", encryptedFilename,
	)

	err = os.Remove(filename)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func decryptFile(encryptedFilename string, key []byte, toDisk bool) ([]byte, error) {
	encryptedFile, err := os.Open(encryptedFilename)
	if err != nil {
		return nil, err
	}
	defer encryptedFile.Close()

	iv := make([]byte, aes.BlockSize)
	_, err = encryptedFile.Read(iv)
	if err != nil {
		return nil, err
	}

	ciphertext, err := io.ReadAll(encryptedFile)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	paddingLength := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-paddingLength]

	if toDisk {
		decryptedFilename := strings.TrimSuffix(encryptedFilename, ".enc")
		decryptedFile, err := os.Create(decryptedFilename)
		if err != nil {
			return nil, err
		}
		defer decryptedFile.Close()

		_, err = decryptedFile.Write(plaintext)
		if err != nil {
			return nil, err
		}

		log.Debugw("File decrypted successfully and saved as:",
			"decryptedFilename", decryptedFilename,
		)

		return nil, nil

	} else {
		return plaintext, nil
	}
}