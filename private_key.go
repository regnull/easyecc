package easyecc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/btcsuite/btcd/btcec"
	ecies "github.com/ecies/go"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	PBKDF2_ITER = 16384
	PBKDF2_SIZE = 32
)

type EllipticCurve int

const (
	SECP256K1 EllipticCurve = 1
	P256      EllipticCurve = 2
	P384      EllipticCurve = 3
	P521      EllipticCurve = 4
)

func getCurve(curve EllipticCurve) elliptic.Curve {
	switch curve {
	case SECP256K1:
		return btcec.S256()
	case P256:
		return elliptic.P256()
	case P384:
		return elliptic.P384()
	case P521:
		return elliptic.P521()
	}
	return nil
}

func getKeyLength(curve EllipticCurve) int {
	switch curve {
	case SECP256K1:
		return 32
	case P256:
		return 32
	case P384:
		return 48
	case P521:
		return 66
	}
	return -1
}

// PrivateKey represents elliptic cryptography private key.
type PrivateKey struct {
	privateKey *ecdsa.PrivateKey
}

// NewRandomPrivateKey creates a new random private key using SECP256K1 curve.
//
// Deprecated: Use GeneratePrivateKey instead.
func NewRandomPrivateKey() (*PrivateKey, error) {
	return GeneratePrivateKey(SECP256K1)
}

// GeneratePrivateKey creates a new random private key,
// given a curve.
func GeneratePrivateKey(curve EllipticCurve) (*PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(getCurve(curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key, %w", err)
	}
	return &PrivateKey{privateKey: privateKey}, nil
}

// NewPrivateKey returns new private key created from the secret using SECP256K1 curve.
//
// Deprecated: Use CreatePrivateKey instead.
func NewPrivateKey(secret *big.Int) *PrivateKey {
	return CreatePrivateKey(SECP256K1, secret)
}

// CreatePrivateKey creates a private key on the given curve from secret.
func CreatePrivateKey(curve EllipticCurve, secret *big.Int) *PrivateKey {
	privateKey := &ecdsa.PrivateKey{
		D: secret}
	privateKey.PublicKey.Curve = getCurve(curve)
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(secret.Bytes())
	return &PrivateKey{privateKey: privateKey}
}

// NewPrivateKeyFromPassword creates a new private key from password and salt using SECP256K1 curve.
//
// Deprecated: Use CreatePrivateKeyFromPassword.
func NewPrivateKeyFromPassword(password, salt []byte) *PrivateKey {
	return CreatePrivateKeyFromPassword(SECP256K1, password, salt)
}

// CreatePrivateKeyFromPassword creates a private key on the given curve from password using PBKDF2 algorithm.
func CreatePrivateKeyFromPassword(curve EllipticCurve, password, salt []byte) *PrivateKey {
	secret := pbkdf2.Key(password, salt, PBKDF2_ITER, PBKDF2_SIZE, sha256.New)
	return CreatePrivateKey(curve, new(big.Int).SetBytes(secret))
}

// NewPrivateKeyFromEncryptedWithPassphrase creates a new private key using SECP256K1 curve
// from encrypted private key using the passphrase.
//
// Deprecated: Use CreatePrivateKeyFromEncrypted instead.
func NewPrivateKeyFromEncryptedWithPassphrase(data []byte, passphrase string) (*PrivateKey, error) {
	return CreatePrivateKeyFromEncrypted(SECP256K1, data, passphrase)
}

// CreatePrivateKeyFromEncrypted creates a private key from from encrypted private
// key using the passphrase.
func CreatePrivateKeyFromEncrypted(curve EllipticCurve, data []byte, passphrase string) (*PrivateKey,
	error) {
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
	return CreatePrivateKey(curve, secret), nil
}

// NewPrivateKeyFromFile loads private key using SECP256K1 curve
// from file and decrypts it using the given passphrase.
// If the passphrase is an empty string, no decryption is done (the file content is assumed
// to be not encrypted).
//
// Deprecated: Use CreatePrivateKeyFromFile instead.
func NewPrivateKeyFromFile(fileName string, passphrase string) (*PrivateKey, error) {
	b, err := os.ReadFile(fileName)
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

// NewPrivateKeyFromFile loads private key using given curve
// from file and decrypts it using the given passphrase.
// If the passphrase is an empty string, no decryption is done (the file content is assumed
// to be not encrypted).
func CreatePrivateKeyFromFile(curve EllipticCurve, fileName string, passphrase string) (*PrivateKey, error) {
	b, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	if passphrase != "" {
		return NewPrivateKeyFromEncryptedWithPassphrase(b, passphrase)
	}

	secret := new(big.Int)
	secret.SetBytes(b)
	return CreatePrivateKey(curve, secret), nil
}

// NewPrivateKeyFromMnemonic creates private key on SECP256K1 curve from a mnemonic phrase.
//
// Deprecated: Use CreateFromMnemonic instead.
func NewPrivateKeyFromMnemonic(mnemonic string) (*PrivateKey, error) {
	b, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	secret := new(big.Int).SetBytes(b)
	return NewPrivateKey(secret), nil
}

// NewPrivateKeyFromMnemonic creates private key on given curve from a mnemonic phrase.
func CreateFromMnemonic(curve EllipticCurve, mnemonic string) (*PrivateKey, error) {
	b, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	secret := new(big.Int).SetBytes(b)
	return CreatePrivateKey(curve, secret), nil
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
		return os.WriteFile(fileName, data, 0600)
	}

	// Pad with zero bytes if necessary.
	b := pk.privateKey.D.Bytes()
	if len(b) < 32 {
		bb := make([]byte, 32-len(b))
		bb = append(bb, b...)
		b = bb
	}
	return os.WriteFile(fileName, b, 0600)
}

// PublicKey returns the public key derived from this private key.
func (pk *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{publicKey: &pk.privateKey.PublicKey}
}

// Curve returns the elliptic curve for this public key.
func (pk *PrivateKey) Curve() EllipticCurve {
	if pk.privateKey.Curve == btcec.S256() {
		return SECP256K1
	}
	if pk.privateKey.Curve == elliptic.P256() {
		return P256
	}
	if pk.privateKey.Curve == elliptic.P384() {
		return P384
	}
	if pk.privateKey.Curve == elliptic.P521() {
		return P521
	}
	return -1
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
	c, err := aes.NewCipher(key[:32]) // The key must be 32 bytes long.
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
	key := sha256.Sum256(pk.privateKey.D.Bytes())
	return encrypt(key[:], content)
}

func decrypt(key []byte, content []byte) ([]byte, error) {
	c, err := aes.NewCipher(key[:32]) // The key must be 32 bytes long.
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
	key := sha256.Sum256(pk.privateKey.D.Bytes())
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

// DecryptECIES decrypts cyphertext that was previously encrypted
// using Elliptic Curve Integrated Encryption Scheme.
// See https://cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme
func (pk *PrivateKey) DecryptECIES(cyphertext []byte) ([]byte, error) {
	k := ecies.NewPrivateKeyFromBytes(pk.privateKey.D.Bytes())
	return ecies.Decrypt(k, cyphertext)
}

func padWithZeros(b []byte, l int) []byte {
	for len(b) < l {
		b = append([]byte{0}, b...)
	}
	return b
}

// GetECDHEncryptionKey returns a shared key that can be used to encrypt data
// exchanged by two parties, using Elliptic Curve Diffie-Hellman algorithm (ECDH).
// For Alice and Bob, the key is guaranteed to be the
// same when it's derived from Alice's private key and Bob's public key or
// Alice's public key and Bob's private key.
//
// See https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman.
//
// This function will return an error when it's used on SECP265K1 curve (because
// it's considered less secure and not supported by crypto/ecdh package).
func (pk *PrivateKey) GetECDHEncryptionKey(publicKey *PublicKey) ([]byte, error) {
	if pk.Curve() != publicKey.Curve() {
		return nil, fmt.Errorf("the keys must be on the same curve")
	}
	var privateKey *ecdh.PrivateKey
	var pubKey *ecdh.PublicKey
	var err error
	switch pk.Curve() {
	case SECP256K1:
		return nil, fmt.Errorf("cannot use ECDH for this curve")
	case P256:
		key := padWithZeros(pk.Secret().Bytes(), getKeyLength(pk.Curve()))
		privateKey, err = ecdh.P256().NewPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pubKey, err = ecdh.P256().NewPublicKey(publicKey.Serialize())
		if err != nil {
			return nil, err
		}
	case P384:
		key := padWithZeros(pk.Secret().Bytes(), getKeyLength(pk.Curve()))
		privateKey, err = ecdh.P384().NewPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pubKey, err = ecdh.P384().NewPublicKey(publicKey.Serialize())
		if err != nil {
			return nil, err
		}
	case P521:
		key := padWithZeros(pk.Secret().Bytes(), getKeyLength(pk.Curve()))
		privateKey, err = ecdh.P521().NewPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pubKey, err = ecdh.P521().NewPublicKey(publicKey.Serialize())
		if err != nil {
			return nil, err
		}
	}
	encryptionKey, err := privateKey.ECDH(pubKey)
	if err != nil {
		return nil, err
	}
	return encryptionKey, nil
}

func (pk *PrivateKey) EncryptECDH(content []byte, publicKey *PublicKey) ([]byte, error) {
	encryptionKey, err := pk.GetECDHEncryptionKey(publicKey)
	if err != nil {
		return nil, err
	}
	return encrypt(encryptionKey, content)
}

func (pk *PrivateKey) DecryptECDH(content []byte, publicKey *PublicKey) ([]byte, error) {
	encryptionKey, err := pk.GetECDHEncryptionKey(publicKey)
	if err != nil {
		return nil, err
	}
	return decrypt(encryptionKey, content)
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
