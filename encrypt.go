package easyecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v3"
	"golang.org/x/crypto/scrypt"
)

const (
	// Key derivation parameters.
	deriveKey_N      = 16384
	deriveKey_r      = 8
	deriveKey_p      = 1
	deriveKey_keyLen = 32
)

// encrypt encrypts the content using AES256-GCM algorithm.
func encrypt(key []byte, content []byte) ([]byte, error) {
	c, err := aes.NewCipher(key[:32]) // The key must be 32 bytes long.
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to populate nonce: %v", err)
	}

	return gcm.Seal(nonce, nonce, content, nil), nil
}

// decrypt decrypts the content using AES256-GCM algorithm.
func decrypt(key []byte, content []byte) ([]byte, error) {
	c, err := aes.NewCipher(key[:32]) // The key must be 32 bytes long.
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(content) < nonceSize {
		return nil, fmt.Errorf("invalid content")
	}

	nonce, ciphertext := content[:nonceSize], content[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	return plaintext, nil
}

// makeSalt creates random 32 bytes salt.
func makeSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// deriveKey creates symmetric encryption key and salt (both are 32 bytes long)
// from password.
// Key derivation algorithm is described in https://www.tarsnap.com/scrypt/scrypt.pdf.
func deriveKey(password, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(password, salt, deriveKey_N, deriveKey_r, deriveKey_p,
		deriveKey_keyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encryptJWS(key []byte, content []byte) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil)
	if err != nil {
		return "", err
	}
	object, err := encrypter.Encrypt(content)
	if err != nil {
		return "", err
	}
	return object.FullSerialize(), nil
}

func addJSONField(content string, name string, value interface{}) (string, error) {
	var i interface{}
	err := json.Unmarshal([]byte(content), &i)
	if err != nil {
		return "", err
	}
	m, ok := i.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid content")
	}
	m[name] = value
	b, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func encryptWithPassphraseJWE(passphrase string, content []byte) (string, error) {
	salt, err := makeSalt()
	if err != nil {
		return "", err
	}
	key, err := deriveKey([]byte(passphrase), salt)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil)
	if err != nil {
		return "", err
	}
	object, err := encrypter.Encrypt(content)
	if err != nil {
		return "", err
	}

	// Add salt field.
	js := object.FullSerialize()
	var i interface{}
	err = json.Unmarshal([]byte(js), &i)
	if err != nil {
		return "", err
	}
	m := i.(map[string]interface{})
	m["x-salt"] = base64urlEncode(salt)
	b, err := json.MarshalIndent(i, "", " ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// encryptWithPassphrase encrypts content with a key derived from the passphrase.
func encryptWithPassphrase(passphrase string, content []byte) ([]byte, error) {
	// This should return JWE.
	salt, err := makeSalt()
	if err != nil {
		return nil, err
	}
	key, err := deriveKey([]byte(passphrase), salt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypt(key, content)
	if err != nil {
		return nil, err
	}
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}