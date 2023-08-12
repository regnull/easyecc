package easyecc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
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

// String returns the elliptic curve name as a string.
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

// StringToEllipticCurve converts the elliptic curve name to EllipticCurve.
// If the name is not recognized, INVALID_CURVE is returned.
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

// getCurve returns elliptic.Curve interface for the given curve.
// If the curve is invalid, the function returns nil.
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

// getKeyLength returns the key length for the given curve,
// or -1 if invalid curve was passed in.
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

// NewPrivateKey creates a new random private key,
// given a curve.
func NewPrivateKey(curve EllipticCurve) (*PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(getCurve(curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key, %v", err)
	}
	return &PrivateKey{privateKey: privateKey}, nil
}

// NewPrivateKeyFromSecret creates a private key on the given curve from secret.
func NewPrivateKeyFromSecret(curve EllipticCurve, secret *big.Int) *PrivateKey {
	privateKey := &ecdsa.PrivateKey{
		D: secret}
	privateKey.PublicKey.Curve = getCurve(curve)
	privateKey.PublicKey.X, privateKey.PublicKey.Y =
		privateKey.PublicKey.Curve.ScalarBaseMult(secret.Bytes())
	return &PrivateKey{privateKey: privateKey}
}

// NewPrivateKeyFromPassword creates a private key on the given curve from password using
// PBKDF2 algorithm.
// See https://en.wikipedia.org/wiki/PBKDF2.
func NewPrivateKeyFromPassword(curve EllipticCurve, password, salt []byte) *PrivateKey {
	secret := pbkdf2.Key(password, salt, PBKDF2_ITER, PBKDF2_SIZE, sha256.New)
	return NewPrivateKeyFromSecret(curve, new(big.Int).SetBytes(secret))
}

// NewPrivateKeyFromFile loads private key from fileName. If no passphrase is give,
// the file is assumed to be in JWK format. If passphrase is given, the file is assumed
// to be in JWE format, containing encrypted JWK key.
func NewPrivateKeyFromFile(fileName string, passphrase string) (*PrivateKey, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	var jsonBytes []byte
	if passphrase != "" {
		jsonBytes, err = decryptWithPassphraseJWE(passphrase, string(data))
		if err != nil {
			return nil, err
		}
	} else {
		jsonBytes = data
	}

	return NewPrivateKeyFromJSON(string(jsonBytes))
}

// NewPrivateKeyFromMnemonic creates private key on given curve from a mnemonic phrase.
// Only SECP256K1 and P256 keys can be created from mnemonic.
func NewPrivateKeyFromMnemonic(curve EllipticCurve, mnemonic string) (*PrivateKey, error) {
	if curve != SECP256K1 && curve != P256 {
		return nil, ErrUnsupportedCurve
	}
	b, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	secret := new(big.Int).SetBytes(b)
	return NewPrivateKeyFromSecret(curve, secret), nil
}

// CreatePrivateKeyFromJSON creates private key from JWK-encoded
// representation.
// See https://www.rfc-editor.org/rfc/rfc7517.
func NewPrivateKeyFromJSON(data string) (*PrivateKey, error) {
	var pkJSON privateKeyJSON
	err := json.Unmarshal([]byte(data), &pkJSON)
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
	return NewPrivateKeyFromSecret(curve, d), nil
}

// Secret returns the private key's secret.
func (pk *PrivateKey) Secret() *big.Int {
	return pk.privateKey.D
}

// Save saves the private key to the specified file. If passphrase is empty, the file
// will contain the key in JWK format. Otherwise, the file will contain encrypted JWK
// key in JWE format.
func (pk *PrivateKey) Save(fileName string, passphrase string) error {
	keyJWK, err := pk.MarshalToJSON()
	if err != nil {
		return err
	}
	content := keyJWK
	if passphrase != "" {
		content, err = encryptWithPassphraseJWE(passphrase, []byte(content))
		if err != nil {
			return err
		}
	}

	return os.WriteFile(fileName, []byte(content), 0600)
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

// getSharedEncryptionKeySecp256k1 computes a shared encryption key for SECP256K1 curve
// in a way that is consistent with how it's done in crypto/ecdh.
func (pk *PrivateKey) getSharedEncryptionKeySecp256k1(counterParty *PublicKey) []byte {
	x, _ := btcec.S256().ScalarMult(counterParty.X(), counterParty.Y(),
		pk.privateKey.D.Bytes())
	return x.Bytes()
}

// EncryptSymmetric encrypts content using this private key. The same private key
// must be used for decryption.
// Encryption is done using AES-256 with CGM cipher.
// TODO: Use JWE here? The function itself would probably go to deprecated package.
func (pk *PrivateKey) EncryptSymmetric(content []byte) ([]byte, error) {
	key := sha256.Sum256(pk.privateKey.D.Bytes())
	return encrypt(key[:], content)
}

// DecryptSymmetric decrypts the content that was previously encrypted using this private key.
// Decryption is done using AES-256 with CGM cipher.
func (pk *PrivateKey) DecryptSymmetric(content []byte) ([]byte, error) {
	key := sha256.Sum256(pk.privateKey.D.Bytes())
	return decrypt(key[:], content)
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
		pubKey, err = ecdh.P256().NewPublicKey(publicKey.Bytes())
		if err != nil {
			return nil, err
		}
	case P384:
		key := padWithZeros(pk.Secret().Bytes(), getKeyLength(pk.Curve()))
		privateKey, err = ecdh.P384().NewPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pubKey, err = ecdh.P384().NewPublicKey(publicKey.Bytes())
		if err != nil {
			return nil, err
		}
	case P521:
		key := padWithZeros(pk.Secret().Bytes(), getKeyLength(pk.Curve()))
		privateKey, err = ecdh.P521().NewPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pubKey, err = ecdh.P521().NewPublicKey(publicKey.Bytes())
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

func (pk *PrivateKey) Encrypt(content []byte, publicKey *PublicKey) ([]byte, error) {
	encryptionKey, err := pk.GetECDHEncryptionKey(publicKey)
	if err != nil {
		return nil, err
	}
	return encrypt(encryptionKey, content)
}

func (pk *PrivateKey) Decrypt(content []byte, publicKey *PublicKey) ([]byte, error) {
	encryptionKey, err := pk.GetECDHEncryptionKey(publicKey)
	if err != nil {
		return nil, err
	}
	return decrypt(encryptionKey, content)
}

// MarshalToJSON returns the key JWK representation,
// see https://www.rfc-editor.org/rfc/rfc7517.
func (pk *PrivateKey) MarshalToJSON() (string, error) {
	xEncoded := base64urlEncode(pk.PublicKey().X().Bytes())
	yEncoded := base64urlEncode(pk.PublicKey().Y().Bytes())
	dEncoded := base64urlEncode(pk.Secret().Bytes())

	b, err := json.Marshal(privateKeyJSON{
		Kty: "EC",
		Crv: pk.Curve().String(),
		X:   xEncoded,
		Y:   yEncoded,
		D:   dEncoded,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}
