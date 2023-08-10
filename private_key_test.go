package easyecc

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

var curves = []EllipticCurve{SECP256K1, P256, P384, P521}

func Test_PrivateKey_EllipticCurveToString(t *testing.T) {
	assert := assert.New(t)

	assert.EqualValues("secp256k1", SECP256K1.String())
	assert.EqualValues("Invalid", INVALID_CURVE.String())
}

func Test_PrivateKey_getCurve(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(elliptic.P256(), getCurve(P256))
	assert.Nil(getCurve(EllipticCurve(999)))
}

func Test_PrivateKey_getKeyLength(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(32, getKeyLength(P256))
	assert.Equal(-1, getKeyLength(EllipticCurve(999)))
}

func Test_PrivateKey_NewRandom(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		pk, err := NewPrivateKey(curve)
		assert.NoError(err)
		assert.NotNil(pk)
	}
}

func Test_PrivateKey_Save(t *testing.T) {
	assert := assert.New(t)

	dir, err := os.MkdirTemp("", "pktest")
	assert.NoError(err)
	for _, curve := range curves {
		pk, err := NewPrivateKey(curve)
		assert.NoError(err)

		fileName := path.Join(dir, fmt.Sprintf("private_key_%v", curve))
		err = pk.Save(fileName, "")
		assert.NoError(err)

		_, err = os.Stat(fileName)
		assert.NoError(err)
	}
	assert.NoError(os.RemoveAll(dir))
}

func Test_PrivateKey_FromPassword(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		key := NewPrivateKeyFromPassword(curve, []byte("super secret spies"), []byte{0x11, 0x22, 0x33, 0x44})
		assert.NotNil(key)
	}
}

func Test_PrivateKey_Mnemonic(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range []EllipticCurve{SECP256K1, P256} {
		key := NewPrivateKeyFromSecret(curve, big.NewInt(123456))
		mnemonic, err := key.Mnemonic()
		assert.NoError(err)

		key1, err := NewPrivateKeyFromMnemonic(curve, mnemonic)
		assert.NoError(err)

		assert.True(key.Equal(key1))
	}

	// Try unsupported curve.
	key, err := NewPrivateKey(P521)
	assert.NoError(err)
	_, err = key.Mnemonic()
	assert.Equal(ErrUnsupportedCurve, err)
	_, err = NewPrivateKeyFromMnemonic(P521, "foo bar baz")
	assert.Equal(ErrUnsupportedCurve, err)

	// Try bad mnemonic.
	_, err = NewPrivateKeyFromMnemonic(SECP256K1, "foo bar baz")
	assert.Error(err)
}

func Test_PrivateKey_Curve(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		key, err := NewPrivateKey(curve)
		assert.NoError(err)
		assert.Equal(curve, key.Curve())
	}
}

func Test_PrivateKey_EncryptECDH(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		aliceKey, err := NewPrivateKey(curve)
		assert.NoError(err)
		bobKey, err := NewPrivateKey(curve)
		assert.NoError(err)

		message := "Putin Huylo"
		encrypted, err := aliceKey.Encrypt([]byte(message), bobKey.PublicKey())
		assert.NoError(err)
		decrypted, err := bobKey.Decrypt(encrypted, aliceKey.PublicKey())
		assert.NoError(err)

		assert.True(bytes.Equal([]byte(message), decrypted))
	}
}

func Test_PrivateKey_ToECDSA(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		privateKey, err := NewPrivateKey(curve)
		assert.NoError(err)
		assert.NotNil(privateKey.ToECDSA())
	}
}

func Test_PrivateKey_ToJWK(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		privateKey, err := NewPrivateKey(curve)
		assert.NoError(err)
		jsonStr, err := privateKey.MarshalToJSON()
		assert.NoError(err)
		assert.True(len(jsonStr) > 10)
		privateKeyCopy, err := NewPrivateKeyFromJSON(jsonStr)
		assert.NoError(err)
		assert.True(privateKey.Equal(privateKeyCopy))
	}

	_, err := NewPrivateKeyFromJSON("{{{{not valid JSON %$##$")
	assert.Error(err)

	_, err = NewPrivateKeyFromJSON("{\"kty\": \"XYZ\"}")
	assert.Equal(ErrUnsupportedKeyType, err)

	_, err = NewPrivateKeyFromJSON("{\"kty\": \"EC\", \"crv\": \"MyCurve\"}")
	assert.Equal(ErrUnsupportedCurve, err)
}

func Test_PrivateKey_SaveAsJWK(t *testing.T) {
	assert := assert.New(t)

	dir, err := os.MkdirTemp("", "pktest")
	assert.NoError(err)
	// Without encryption.
	for _, curve := range curves {
		privateKey, err := NewPrivateKey(curve)
		assert.NoError(err)
		fileName := path.Join(dir, fmt.Sprintf("private_key_%v", curve))
		err = privateKey.Save(fileName, "")
		assert.NoError(err)
		privateKeyCopy, err := NewPrivateKeyFromFile(fileName, "")
		assert.NoError(err)
		assert.True(privateKey.Equal(privateKeyCopy))
	}
	// With encryption.
	passphrase := "potato123"
	for _, curve := range curves {
		privateKey, err := NewPrivateKey(curve)
		assert.NoError(err)
		fileName := path.Join(dir, fmt.Sprintf("private_key_enc_%v", curve))
		err = privateKey.Save(fileName, passphrase)
		assert.NoError(err)
		privateKeyCopy, err := NewPrivateKeyFromFile(fileName, passphrase)
		assert.NoError(err)
		assert.True(privateKey.Equal(privateKeyCopy))
	}
	assert.NoError(os.RemoveAll(dir))

	_, err = NewPrivateKeyFromFile("some_non_existent_file", "foo")
	assert.Error(err)
}
