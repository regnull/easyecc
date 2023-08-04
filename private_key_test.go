package easyecc

import (
	"bytes"
	"math/big"
	"math/rand"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

var curves = []EllipticCurve{SECP256K1, P256, P384, P521}

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

	for _, curve := range curves {
		pk, err := GeneratePrivateKey(curve)
		assert.NoError(err)

		dir, err := os.MkdirTemp("", "pktest")
		assert.NoError(err)

		fileName := path.Join(dir, "private_key")
		err = pk.Save(fileName, "")
		assert.NoError(err)

		_, err = os.Stat(fileName)
		assert.NoError(err)

		assert.NoError(os.RemoveAll(dir))
	}
}

func Test_PrivateKey_SaveWithPassphrase(t *testing.T) {
	assert := assert.New(t)

	passphrase := "super secret password"
	for _, curve := range curves {
		pk, err := GeneratePrivateKey(curve)
		assert.NoError(err)

		dir, err := os.MkdirTemp("", "pktest")
		assert.NoError(err)

		fileName := path.Join(dir, "private_key")
		err = pk.Save(fileName, passphrase)
		assert.NoError(err)

		_, err = os.Stat(fileName)
		assert.NoError(err)

		loadedPk, err := CreatePrivateKeyFromFile(curve, fileName, passphrase)
		assert.NoError(err)
		assert.NotNil(loadedPk)
		assert.True(pk.Equal(loadedPk))

		assert.NoError(os.RemoveAll(dir))
	}
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
		key, err := GeneratePrivateKey(curve)
		assert.NoError(err)
		mnemonic, err := key.Mnemonic()
		assert.NoError(err)

		key1, err := CreatePrivateKeyFromMnemonic(curve, mnemonic)
		assert.NoError(err)

		assert.True(key.Equal(key1))
	}
}

func Test_PrivateKey_PadOnSave(t *testing.T) {
	assert := assert.New(t)

	key := NewPrivateKey(big.NewInt(123))

	dir, err := os.MkdirTemp("", "pktest")
	assert.NoError(err)

	fileName := path.Join(dir, "private_key")
	err = key.Save(fileName, "")
	assert.NoError(err)

	fi, err := os.Stat(fileName)
	assert.NoError(err)
	assert.EqualValues(32, fi.Size())

	key1, err := NewPrivateKeyFromFile(fileName, "")
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
