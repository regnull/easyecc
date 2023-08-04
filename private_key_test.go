package easyecc

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

var curves = []EllipticCurve{SECP256K1, P256, P384, P521}

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
		pk, err := GeneratePrivateKey(curve)
		assert.NoError(err)
		assert.NotNil(pk)
	}
}

func Test_PrivateKey_Save(t *testing.T) {
	assert := assert.New(t)

	dir, err := os.MkdirTemp("", "pktest")
	assert.NoError(err)
	for _, curve := range curves {
		pk, err := GeneratePrivateKey(curve)
		assert.NoError(err)

		fileName := path.Join(dir, fmt.Sprintf("private_key_%v", curve))
		err = pk.Save(fileName, "")
		assert.NoError(err)

		_, err = os.Stat(fileName)
		assert.NoError(err)
	}
	assert.NoError(os.RemoveAll(dir))
}

func Test_PrivateKey_SaveWithPassphrase(t *testing.T) {
	assert := assert.New(t)

	passphrase := "super secret password"
	dir, err := os.MkdirTemp("", "pktest")
	assert.NoError(err)
	for _, curve := range curves {
		pk, err := GeneratePrivateKey(curve)
		assert.NoError(err)

		fileName := path.Join(dir, fmt.Sprintf("private_key_%v", curve))
		err = pk.Save(fileName, passphrase)
		assert.NoError(err)

		_, err = os.Stat(fileName)
		assert.NoError(err)

		if curve == SECP256K1 {
			// Test deprecated function.
			loadedPk, err := NewPrivateKeyFromFile(fileName, passphrase)
			assert.NoError(err)
			assert.NotNil(loadedPk)
		}

		loadedPk, err := CreatePrivateKeyFromFile(curve, fileName, passphrase)
		assert.NoError(err)
		assert.NotNil(loadedPk)
		assert.True(pk.Equal(loadedPk))
	}
	assert.NoError(os.RemoveAll(dir))

	// Test deprecated function.
	_, err = NewPrivateKeyFromFile("some-non-existent-file", "foo")
	assert.Error(err)
}

func Test_PrivateKey_LoadFromBadFile(t *testing.T) {
	assert := assert.New(t)

	_, err := CreatePrivateKeyFromFile(P256, "some-none-existing-file", "foo")
	assert.Error(err)
}

func Test_PrivateKey_Load(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		pk, err := GeneratePrivateKey(curve)
		assert.NoError(err)

		dir, err := os.MkdirTemp("", "pktest")
		assert.NoError(err)

		fileName := path.Join(dir, "private_key")
		err = pk.Save(fileName, "")
		assert.NoError(err)

		pkCopy, err := CreatePrivateKeyFromFile(curve, fileName, "")
		assert.NoError(err)
		assert.NotNil(pkCopy)
		assert.EqualValues(pk.privateKey.D, pkCopy.privateKey.D)
		assert.EqualValues(pk.privateKey.PublicKey.X, pkCopy.privateKey.PublicKey.X)
		assert.EqualValues(pk.privateKey.PublicKey.Y, pkCopy.privateKey.PublicKey.Y)

		assert.NoError(os.RemoveAll(dir))
	}
}

func Test_PrivateKey_SerializeDeserialize(t *testing.T) {
	assert := assert.New(t)

	// Confirm that serialization/deserialization work as expected.
	// Serialize/deserialize a bunch of keys.

	r := rand.New(rand.NewSource(123))
	for _, curve := range curves {
		for i := 0; i < 1000; i++ {
			secret := r.Int63()
			privateKey := CreatePrivateKey(curve, big.NewInt(secret))
			serialized := privateKey.PublicKey().SerializeCompressed()
			publicKey, err := DeserializeCompressed(curve, serialized)
			assert.NoError(err)
			assert.Equal(privateKey.PublicKey().publicKey.X, publicKey.publicKey.X)
			assert.Equal(privateKey.PublicKey().publicKey.Y, publicKey.publicKey.Y)
		}
	}
}

func Test_PrivateKey_EncryptDecrypt(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		key, err := GeneratePrivateKey(curve)
		assert.NoError(err)

		encrypted, err := key.EncryptKeyWithPassphrase("super secret spies")
		assert.NoError(err)
		assert.NotNil(encrypted)

		key1, err := CreatePrivateKeyFromEncrypted(curve, encrypted, "super secret spies")
		assert.NoError(err)
		assert.True(key1.privateKey.Equal(key.privateKey))
	}
}

func Test_PrivateKey_FromPassword(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		key := CreatePrivateKeyFromPassword(curve, []byte("super secret spies"), []byte{0x11, 0x22, 0x33, 0x44})
		assert.NotNil(key)
	}

	// Deprecated function.
	key := NewPrivateKeyFromPassword([]byte("super secret spies"), []byte{0x11, 0x22, 0x33, 0x44})
	assert.NotNil(key)
}

func Test_PrivateKey_NewPrivateKeyFromEncryptedWithPassphrase_InvalidData(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		key, err := CreatePrivateKeyFromEncrypted(curve, []byte("bad data"), "foo")
		assert.Nil(key)
		assert.Error((err))
	}
}

func Test_PrivateKey_Mnemonic(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range []EllipticCurve{SECP256K1, P256} {
		key := CreatePrivateKey(curve, big.NewInt(123456))
		mnemonic, err := key.Mnemonic()
		assert.NoError(err)

		key1, err := CreatePrivateKeyFromMnemonic(curve, mnemonic)
		assert.NoError(err)

		assert.True(key.Equal(key1))
	}

	// Try unsupported curve.
	_, err := CreatePrivateKeyFromMnemonic(P521, "foo bar baz")
	assert.Equal(ErrUnsupportedCurve, err)

	// Try bad mnemonic.
	_, err = CreatePrivateKeyFromMnemonic(SECP256K1, "foo bar baz")
	assert.Error(err)

	// Deprecated function.
	key := CreatePrivateKey(SECP256K1, big.NewInt(123456))
	mnemonic, err := key.Mnemonic()
	assert.NoError(err)

	key1, err := NewPrivateKeyFromMnemonic(mnemonic)
	assert.NoError(err)

	assert.True(key.Equal(key1))
}

func Test_PrivateKey_PadOnSave(t *testing.T) {
	assert := assert.New(t)

	key := CreatePrivateKey(SECP256K1, big.NewInt(123))

	dir, err := os.MkdirTemp("", "pktest")
	assert.NoError(err)

	fileName := path.Join(dir, "private_key")
	err = key.Save(fileName, "")
	assert.NoError(err)

	fi, err := os.Stat(fileName)
	assert.NoError(err)
	assert.EqualValues(32, fi.Size())

	key1, err := CreatePrivateKeyFromFile(SECP256K1, fileName, "")
	assert.NoError(err)

	assert.True(key.Equal(key1))

	assert.NoError(os.RemoveAll(dir))
}

func Test_PrivateKey_Curve(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		key, err := GeneratePrivateKey(curve)
		assert.NoError(err)
		assert.Equal(curve, key.Curve())
	}
}

func Test_PrivateKey_EncryptECDH(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		aliceKey, err := GeneratePrivateKey(curve)
		assert.NoError(err)
		bobKey, err := GeneratePrivateKey(curve)
		assert.NoError(err)

		message := "Putin Huylo"
		encrypted, err := aliceKey.EncryptECDH([]byte(message), bobKey.PublicKey())
		assert.NoError(err)
		decrypted, err := bobKey.DecryptECDH(encrypted, aliceKey.PublicKey())
		assert.NoError(err)

		assert.True(bytes.Equal([]byte(message), decrypted))
	}
}

func Test_PrivateKey_EncryptLegacy(t *testing.T) {
	assert := assert.New(t)

	curve := SECP256K1 // Legacy encryption works only on this curve.
	aliceKey, err := GeneratePrivateKey(curve)
	assert.NoError(err)
	bobKey, err := GeneratePrivateKey(curve)
	assert.NoError(err)

	message := "Putin Huylo"
	encrypted, err := aliceKey.Encrypt([]byte(message), bobKey.PublicKey())
	assert.NoError(err)
	decrypted, err := bobKey.Decrypt(encrypted, aliceKey.PublicKey())
	assert.NoError(err)

	assert.True(bytes.Equal([]byte(message), decrypted))

	// Try unsupported curve.
	spongeBobKey, err := GeneratePrivateKey(P521)
	assert.NoError(err)
	encrypted, err = spongeBobKey.Encrypt([]byte(message), bobKey.PublicKey())
	assert.Equal(ErrUnsupportedCurve, err)

	_, err = spongeBobKey.Decrypt(encrypted, aliceKey.PublicKey())
	assert.Equal(ErrUnsupportedCurve, err)
}

func Test_PrivateKey_ToECDSA(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		privateKey, err := GeneratePrivateKey(curve)
		assert.NoError(err)
		assert.NotNil(privateKey.ToECDSA())
	}
}
