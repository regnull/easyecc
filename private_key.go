package easyecc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// PrivateKey represents elliptic cryptography private key.
type PrivateKey struct {
	privateKey *ecdsa.PrivateKey
}

// NewRandomPrivateKey creates a new random private key.
func NewRandomPrivateKey() (*PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key, %w", err)
	}
	return &PrivateKey{privateKey: privateKey}, nil
}

// NewPrivateKey returns new private key created from the secret.
func NewPrivateKey(secret *big.Int) *PrivateKey {
	privateKey := &ecdsa.PrivateKey{
		D: secret}
	privateKey.PublicKey.Curve = btcec.S256()
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(secret.Bytes())
	return &PrivateKey{privateKey: privateKey}
}

// NewPrivateKeyFromPassword creates a new private key from password and salt.
func NewPrivateKeyFromPassword(password, salt []byte) *PrivateKey {
	secret := pbkdf2.Key(password, salt, 16384, 32, sha256.New)
	return NewPrivateKey(new(big.Int).SetBytes(secret))
}

// NewPrivateKeyFromEncryptedWithPassphrase creates a new private key from encrypted private key
// using the passphrase.
func NewPrivateKeyFromEncryptedWithPassphrase(data []byte, passphrase string) (*PrivateKey, error) {
	if len(data) < 33 {
		return nil, fmt.Errorf("invalid data")
	}
	salt, data := data[len(data)-32:], data[:len(data)-32]
	key, _, err := deriveKey([]byte(passphrase), salt)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	keyBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	secret := new(big.Int).SetBytes(keyBytes)
	return NewPrivateKey(secret), nil
}

// LoadPrivateKey loads private key from file and decrypts it using the given passphrase.
// If the passphrase is an empty string, no decryption is done (the file content is assumed
// to be not encrypted).
func NewPrivateKeyFromFile(fileName string, passphrase string) (*PrivateKey, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	if len(b) < 32 {
		return nil, fmt.Errorf("invalid private key length")
	}

	if passphrase != "" {
		return NewPrivateKeyFromEncryptedWithPassphrase(b, passphrase)
	}

	if len(b) != 32 {
		return nil, fmt.Errorf("invalid private key length")
	}

	secret := new(big.Int)
	secret.SetBytes(b)
	return NewPrivateKey(secret), nil
}

// NewPrivateKeyFromMnemonic creates private key from a mnemonic phrase.
func NewPrivateKeyFromMnemonic(mnemonic string) (*PrivateKey, error) {
	b, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	secret := new(big.Int).SetBytes(b)
	return NewPrivateKey(secret), nil
}

// Secret returns the private key's secret.
func (pk *PrivateKey) Secret() *big.Int {
	return pk.privateKey.D
}

// Save saves the private key to the specified file. If the passphrase is given, the key will
// be encrypted with this passphrase. If the passphrase is an empty string, the key is not
// encrypted.
func (pk *PrivateKey) Save(fileName string, passphrase string) error {
	if passphrase != "" {
		data, err := pk.EncryptKeyWithPassphrase(passphrase)
		if err != nil {
			return err
		}
		return ioutil.WriteFile(fileName, data, 0600)
	}

	return ioutil.WriteFile(fileName, []byte(pk.privateKey.D.Bytes()), 0600)
}

// PublicKey returns the public key derived from this private key.
func (pk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{publicKey: &pk.privateKey.PublicKey}
}

// Sign signs the hash using the private key and returns signature.
func (pk *PrivateKey) Sign(hash []byte) (*Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, pk.privateKey, hash)
	if err != nil {
		return nil, err
	}
	return &Signature{R: r, S: s}, nil
}

// GetSharedEncryptionKey returns a shared key that can be used to encrypt communications
// between two parties.
func (pk *PrivateKey) GetSharedEncryptionKey(counterParty *PublicKey) []byte {
	x, y := btcec.S256().ScalarMult(counterParty.X(), counterParty.Y(),
		pk.privateKey.D.Bytes())
	b := bytes.Join([][]byte{x.Bytes(), y.Bytes()}, nil)
	hash := sha256.Sum256(b)
	return hash[:]
}

func encrypt(key []byte, content []byte) ([]byte, error) {
	c, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to populate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, content, nil), nil
}

// Encrypt encrypts content with a shared key derived from this private key and the
// counterparty's public key.
func (pk *PrivateKey) Encrypt(content []byte, publicKey *PublicKey) ([]byte, error) {
	encryptionKey := pk.GetSharedEncryptionKey(publicKey)
	return encrypt(encryptionKey, content)
}

// EncryptSymmetric encrypts content using this private key. The same private key
// must be used for decryption.
func (pk *PrivateKey) EncryptSymmetric(content []byte) ([]byte, error) {
	key := sha256.Sum256(pk.privateKey.X.Bytes())
	return encrypt(key[:], content)
}

func decrypt(key []byte, content []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(content) < nonceSize {
		return nil, fmt.Errorf("invalid content")
	}

	nonce, ciphertext := content[:nonceSize], content[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return plaintext, nil
}

// Decrypt decrypts content with a shared key derived from this private key and the
// counterparty's public key.
func (pk *PrivateKey) Decrypt(content []byte, publicKey *PublicKey) ([]byte, error) {
	encryptionKey := pk.GetSharedEncryptionKey(publicKey)
	return decrypt(encryptionKey, content)
}

// DecryptSymmetric decrypts the content that was previously encrypted using this private key.
func (pk *PrivateKey) DecryptSymmetric(content []byte) ([]byte, error) {
	key := sha256.Sum256(pk.privateKey.X.Bytes())
	return decrypt(key[:], content)
}

// EncryptKeyWithPassphrase encrypts this private key using a passphrase.
func (pk *PrivateKey) EncryptKeyWithPassphrase(passphrase string) ([]byte, error) {
	key, salt, err := deriveKey([]byte(passphrase), nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, pk.privateKey.D.Bytes(), nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

// Mnemonic returns a mnemonic phrase which can be used to recover this private key.
func (pk *PrivateKey) Mnemonic() (string, error) {
	return bip39.NewMnemonic(pk.privateKey.D.Bytes())
}

// Equal returns true if this key is equal to the other key.
func (pk *PrivateKey) Equal(other *PrivateKey) bool {
	return pk.privateKey.D.Cmp(other.privateKey.D) == 0
}

// ToECDSA returns this key as crypto/ecdsa private key.
func (pk *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return pk.privateKey
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}
