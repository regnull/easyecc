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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/go-jose/go-jose/v3"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	PBKDF2_ITER = 16384
	PBKDF2_SIZE = 32
)

var ErrUnsupportedCurve = fmt.Errorf("the operation is not supported on this curve")
var ErrDifferentCurves = fmt.Errorf("the keys must use the same curve")
var ErrUnsupportedKeyType = fmt.Errorf("unsupported key type")

type EllipticCurve int

const (
	INVALID_CURVE EllipticCurve = -1
	SECP256K1     EllipticCurve = 1
	P256          EllipticCurve = 2
	P384          EllipticCurve = 3
	P521          EllipticCurve = 4
)

func (ec EllipticCurve) String() string {
	switch ec {
	case SECP256K1:
		return "secp256k1"
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	case P521:
		return "P-521"
	}
	return "Invalid"
}

func StringToEllipticCurve(s string) EllipticCurve {
	switch strings.ToUpper(s) {
	case "SECP256K1":
		return SECP256K1
	case "P-256":
		return P256
	case "P-384":
		return P384
	case "P-521":
		return P521
	}

	return INVALID_CURVE
}

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

// privateKeyJSON struct is used when serializing keys to JWK format.
type privateKeyJSON struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// GeneratePrivateKey creates a new random private key,
// given a curve.
func GeneratePrivateKey(curve EllipticCurve) (*PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(getCurve(curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key, %v", err)
	}
	return &PrivateKey{privateKey: privateKey}, nil
}

// CreatePrivateKey creates a private key on the given curve from secret.
func CreatePrivateKey(curve EllipticCurve, secret *big.Int) *PrivateKey {
	privateKey := &ecdsa.PrivateKey{
		D: secret}
	privateKey.PublicKey.Curve = getCurve(curve)
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(secret.Bytes())
	return &PrivateKey{privateKey: privateKey}
}

// CreatePrivateKeyFromPassword creates a private key on the given curve from password using PBKDF2 algorithm.
func CreatePrivateKeyFromPassword(curve EllipticCurve, password, salt []byte) *PrivateKey {
	secret := pbkdf2.Key(password, salt, PBKDF2_ITER, PBKDF2_SIZE, sha256.New)
	return CreatePrivateKey(curve, new(big.Int).SetBytes(secret))
}

// CreatePrivateKeyFromEncrypted creates a private key from from encrypted private
// key using the passphrase.
// Encryption is done using AES-256 with CGM cipher, with a key derived from the passphrase.
func CreatePrivateKeyFromEncrypted(curve EllipticCurve, data []byte, passphrase string) (*PrivateKey,
	error) {
	// Data length must be the key length plus at least one more byte.
	// TODO: This doesn't look like a useful check.
	if len(data) < getKeyLength(curve)+1 {
		return nil, fmt.Errorf("invalid data")
	}
	salt, data := data[len(data)-32:], data[:len(data)-32]

	key, _, err := deriveKey([]byte(passphrase), salt)
	if err != nil {
		return nil, err
	}

	keyBytes, err := decrypt(key, data)
	if err != nil {
		return nil, err
	}

	secret := new(big.Int).SetBytes(keyBytes)
	return CreatePrivateKey(curve, secret), nil
}

// NewPrivateKeyFromFile loads private key using given curve
// from file and decrypts it using the given passphrase.
// If the passphrase is an empty string, no decryption is done (the file content is assumed
// to be not encrypted).
func CreatePrivateKeyFromFile(curve EllipticCurve, fileName string, passphrase string) (*PrivateKey, error) {
	// TODO: Perhaps rename this function to something like LoadPrivateKey in the next major version?
	b, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	if passphrase != "" {
		return CreatePrivateKeyFromEncrypted(curve, b, passphrase)
	}

	secret := new(big.Int)
	secret.SetBytes(b)
	return CreatePrivateKey(curve, secret), nil
}

// CreatePrivateKeyFromJWKFile loads private key from file in JWK format, optionally
// decrypting it.
func CreatePrivateKeyFromJWKFile(fileName string, passphrase string) (*PrivateKey, error) {
	// TODO: Rename this to LoadPrivateKeyAsJWK in the next major version.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	var jsonBytes []byte
	if passphrase != "" {
		salt, data := data[len(data)-32:], data[:len(data)-32]
		key, _, err := deriveKey([]byte(passphrase), salt)
		if err != nil {
			return nil, err
		}

		jsonBytes, err = decrypt(key, data)
		if err != nil {
			return nil, err
		}
	} else {
		jsonBytes = data
	}

	return CreatePrivateKeyFromJWK(jsonBytes)
}

// NewPrivateKeyFromMnemonic creates private key on given curve from a mnemonic phrase.
func CreatePrivateKeyFromMnemonic(curve EllipticCurve, mnemonic string) (*PrivateKey, error) {
	if curve != SECP256K1 && curve != P256 {
		return nil, ErrUnsupportedCurve
	}
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

func base64urlEncode(data []byte) string {
	return base64.StdEncoding.
		WithPadding(base64.NoPadding).
		EncodeToString(data)
}

func base64urlDecode(s string) ([]byte, error) {
	return base64.
		StdEncoding.WithPadding(base64.NoPadding).
		DecodeString(s)
}

// CreatePrivateKeyFromJWK creates private key from JWK-encoded
// representation.
// See https://www.rfc-editor.org/rfc/rfc7517.
func CreatePrivateKeyFromJWK(data []byte) (*PrivateKey, error) {
	var pkJSON privateKeyJSON
	err := json.Unmarshal(data, &pkJSON)
	if err != nil {
		return nil, err
	}
	if pkJSON.Kty != "EC" {
		return nil, ErrUnsupportedKeyType
	}
	curve := StringToEllipticCurve(pkJSON.Crv)
	if curve == INVALID_CURVE {
		return nil, ErrUnsupportedCurve
	}
	// JWK uses Base64url encoding, which is Base64 encoding without padding.
	dBytes, err := base64urlDecode(pkJSON.D)
	if err != nil {
		return nil, err
	}
	d := new(big.Int)
	d.SetBytes(dBytes)
	return CreatePrivateKey(curve, d), nil
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
	b := padWithZeros(pk.privateKey.D.Bytes(), getKeyLength(pk.Curve()))
	return os.WriteFile(fileName, b, 0600)
}

// SaveAsJWK writes the key to a file in JWK format, optionally encrypting it
// with a passphrase.
func (pk *PrivateKey) SaveAsJWK(fileName string, passphrase string) error {
	jsonBytes, err := pk.MarshalToJWK()
	if err != nil {
		return err
	}
	if passphrase != "" {
		data, err := encryptWithPassphrase(passphrase, jsonBytes)
		if err != nil {
			return err
		}
		return os.WriteFile(fileName, data, 0600)
	}

	return os.WriteFile(fileName, jsonBytes, 0600)
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
	return INVALID_CURVE
}

// Sign signs (ECDSA) the hash using the private key and returns signature.
// See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm.
func (pk *PrivateKey) Sign(hash []byte) (*Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, pk.privateKey, hash)
	if err != nil {
		return nil, err
	}
	return &Signature{R: r, S: s}, nil
}

// getSharedEncryptionKeySecp256k1_Legacy computes a shared encryption key for SECP256K1 curve
// in a way that is consistent with how it's done in crypto/ecdh.
// This is the old way of doing this, which is somewhat different from what crypto/ecdh does.
// The latter returns X coordinate bytes while we join X and Y and hash the result.
func (pk *PrivateKey) getSharedEncryptionKeySecp256k1_Legacy(counterParty *PublicKey) []byte {
	x, y := btcec.S256().ScalarMult(counterParty.X(), counterParty.Y(),
		pk.privateKey.D.Bytes())
	b := bytes.Join([][]byte{x.Bytes(), y.Bytes()}, nil)
	hash := sha256.Sum256(b)
	return hash[:]
}

// getSharedEncryptionKeySecp256k1 computes a shared encryption key for SECP256K1 curve
// in a way that is consistent with how it's done in crypto/ecdh.
func (pk *PrivateKey) getSharedEncryptionKeySecp256k1(counterParty *PublicKey) []byte {
	x, _ := btcec.S256().ScalarMult(counterParty.X(), counterParty.Y(),
		pk.privateKey.D.Bytes())
	return x.Bytes()
}

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

// EncryptSymmetric encrypts content using this private key. The same private key
// must be used for decryption.
// Encryption is done using AES-256 with CGM cipher.
func (pk *PrivateKey) EncryptSymmetric(content []byte) ([]byte, error) {
	key := sha256.Sum256(pk.privateKey.D.Bytes())
	return encrypt(key[:], content)
}

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

// DecryptSymmetric decrypts the content that was previously encrypted using this private key.
// Decryption is done using AES-256 with CGM cipher.
func (pk *PrivateKey) DecryptSymmetric(content []byte) ([]byte, error) {
	key := sha256.Sum256(pk.privateKey.D.Bytes())
	return decrypt(key[:], content)
}

func encryptWithPassphrase(passphrase string, content []byte) ([]byte, error) {
	key, salt, err := deriveKey([]byte(passphrase), nil)
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

func encryptWithPassphraseJWE(passphrase string, content []byte) (string, error) {
	key, salt, err := deriveKey([]byte(passphrase), nil)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil)
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

func decryptWithPassphraseJWE(passphrase string, content string) ([]byte, error) {
	var i interface{}
	err := json.Unmarshal([]byte(content), &i)
	if err != nil {
		return nil, err
	}
	m, ok := i.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid content")
	}
	saltStr, ok := m["x-salt"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid content")
	}
	salt, err := base64urlDecode(saltStr)
	if err != nil {
		return nil, fmt.Errorf("invalid content")
	}
	key, _, err := deriveKey([]byte(passphrase), salt)
	if err != nil {
		return nil, err
	}
	object, err := jose.ParseEncrypted(content)
	if err != nil {
		return nil, err
	}
	return object.Decrypt(key)
}

// EncryptKeyWithPassphrase encrypts this private key using a passphrase.
// Encryption is done using AES-256 with CGM cipher, with a key derived from the passphrase.
func (pk *PrivateKey) EncryptKeyWithPassphrase(passphrase string) ([]byte, error) {
	return encryptWithPassphrase(passphrase, pk.privateKey.D.Bytes())
}

// Mnemonic returns a mnemonic phrase which can be used to recover this private key.
func (pk *PrivateKey) Mnemonic() (string, error) {
	if pk.Curve() != SECP256K1 && pk.Curve() != P256 {
		return "", ErrUnsupportedCurve
	}
	return bip39.NewMnemonic(padWithZeros(pk.privateKey.D.Bytes(), 32))
}

// Equal returns true if this key is equal to the other key.
func (pk *PrivateKey) Equal(other *PrivateKey) bool {
	return pk.privateKey.D.Cmp(other.privateKey.D) == 0
}

// ToECDSA returns this key as crypto/ecdsa private key.
func (pk *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return pk.privateKey
}

// GetECDHEncryptionKey returns a shared key that can be used to encrypt data
// exchanged by two parties, using Elliptic Curve Diffie-Hellman algorithm (ECDH).
// For Alice and Bob, the key is guaranteed to be the
// same when it's derived from Alice's private key and Bob's public key or
// Alice's public key and Bob's private key.
//
// See https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman.
func (pk *PrivateKey) GetECDHEncryptionKey(publicKey *PublicKey) ([]byte, error) {
	if pk.Curve() != publicKey.Curve() {
		return nil, ErrDifferentCurves
	}
	var privateKey *ecdh.PrivateKey
	var pubKey *ecdh.PublicKey
	var err error
	switch pk.Curve() {
	case SECP256K1:
		// This curve is not supported by crypto/ecdh, so we have to handle
		// it as a special case.
		encryptionKey := pk.getSharedEncryptionKeySecp256k1(publicKey)
		return padWithZeros(encryptionKey, 32), nil
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

// MarshalToJWK returns the key JWK representation,
// see https://www.rfc-editor.org/rfc/rfc7517.
func (pk *PrivateKey) MarshalToJWK() ([]byte, error) {
	xEncoded := base64urlEncode(pk.PublicKey().X().Bytes())
	yEncoded := base64urlEncode(pk.PublicKey().Y().Bytes())
	dEncoded := base64urlEncode(pk.Secret().Bytes())

	return json.MarshalIndent(privateKeyJSON{
		Kty: "EC",
		Crv: pk.Curve().String(),
		X:   xEncoded,
		Y:   yEncoded,
		D:   dEncoded,
	}, "", "  ")
}

// deriveKey creates symmetric encryption key and salt (both are 32 bytes long)
// from password. If salt is not given (nil), new random one is created.
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

func padWithZeros(b []byte, l int) []byte {
	for len(b) < l {
		b = append([]byte{0}, b...)
	}
	return b
}

// Everything below is deprecated.

// NewRandomPrivateKey creates a new random private key using SECP256K1 curve.
//
// Deprecated: Use GeneratePrivateKey instead.
func NewRandomPrivateKey() (*PrivateKey, error) {
	return GeneratePrivateKey(SECP256K1)
}

// NewPrivateKey returns new private key created from the secret using SECP256K1 curve.
//
// Deprecated: Use CreatePrivateKey instead.
func NewPrivateKey(secret *big.Int) *PrivateKey {
	return CreatePrivateKey(SECP256K1, secret)
}

// NewPrivateKeyFromPassword creates a new private key from password and salt using SECP256K1 curve.
//
// Deprecated: Use CreatePrivateKeyFromPassword.
func NewPrivateKeyFromPassword(password, salt []byte) *PrivateKey {
	return CreatePrivateKeyFromPassword(SECP256K1, password, salt)
}

// NewPrivateKeyFromEncryptedWithPassphrase creates a new private key using SECP256K1 curve
// from encrypted private key using the passphrase.
//
// Deprecated: Use CreatePrivateKeyFromEncrypted instead.
func NewPrivateKeyFromEncryptedWithPassphrase(data []byte, passphrase string) (*PrivateKey, error) {
	return CreatePrivateKeyFromEncrypted(SECP256K1, data, passphrase)
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

// NewPrivateKeyFromMnemonic creates private key on SECP256K1 curve from a mnemonic phrase.
//
// Deprecated: Use CreatePrivateKeyFromMnemonic instead.
func NewPrivateKeyFromMnemonic(mnemonic string) (*PrivateKey, error) {
	return CreatePrivateKeyFromMnemonic(SECP256K1, mnemonic)
}

// Encrypt encrypts content with a shared key derived from this private key and the
// counter party public key. Works only on secp256k1 curve.
//
// Deprecated: Use EncryptECDH instead, which works on all supported curves.
// Notice that Encrypt/Decrypt and EncryptECDH/DecryptECDH are not compatible on
// secp256k1 curve, since they are using different ways of generating shared encryption key.
func (pk *PrivateKey) Encrypt(content []byte, publicKey *PublicKey) ([]byte, error) {
	if pk.Curve() != SECP256K1 {
		return nil, ErrUnsupportedCurve
	}
	encryptionKey := pk.getSharedEncryptionKeySecp256k1_Legacy(publicKey)
	return encrypt(encryptionKey, content)
}

// Decrypt decrypts content with a shared key derived from this private key and the
// counter party public key.
//
// Deprecated: Use DecryptECDH instead, which works on all supported curves.
// Notice that Encrypt/Decrypt and EncryptECDH/DecryptECDH are not compatible on
// secp256k1 curve, since they are using different ways of generating shared encryption key.
func (pk *PrivateKey) Decrypt(content []byte, publicKey *PublicKey) ([]byte, error) {
	if pk.Curve() != SECP256K1 {
		return nil, ErrUnsupportedCurve
	}
	encryptionKey := pk.getSharedEncryptionKeySecp256k1_Legacy(publicKey)
	return decrypt(encryptionKey, content)
}
