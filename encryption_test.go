package easyecc

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
)

func TestEncryption(t *testing.T) {
	assert := assert.New(t)

	alicePrivateKey, err := NewRandomPrivateKey()
	assert.NoError(err)

	bobPrivateKey, err := NewRandomPrivateKey()
	assert.NoError(err)

	key1x, key1y := btcec.S256().ScalarMult(alicePrivateKey.PublicKey().X(), alicePrivateKey.PublicKey().Y(),
		bobPrivateKey.Secret().Bytes())

	key2x, key2y := btcec.S256().ScalarMult(bobPrivateKey.PublicKey().X(), bobPrivateKey.PublicKey().Y(),
		alicePrivateKey.Secret().Bytes())

	assert.Equal(key1x, key2x)
	assert.Equal(key1y, key2y)
}

func TestEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)

	alicePrivateKey, err := NewRandomPrivateKey()
	assert.NoError(err)

	bobPrivateKey, err := NewRandomPrivateKey()
	assert.NoError(err)

	message := "a"
	ciphertext, err := alicePrivateKey.Encrypt([]byte(message), bobPrivateKey.PublicKey())
	assert.NoError(err)

	plaintext, err := bobPrivateKey.Decrypt(ciphertext, alicePrivateKey.PublicKey())
	assert.NoError(err)

	assert.True(bytes.Equal([]byte(message), plaintext))
}

func TestEncryptDecryptSymmetric(t *testing.T) {
	assert := assert.New(t)

	privateKey, err := NewRandomPrivateKey()
	assert.NoError(err)

	message := "super secret message"
	encrypted, err := privateKey.EncryptSymmetric([]byte(message))
	assert.NoError(err)

	assert.True(len(encrypted) > len([]byte(message)))

	decrypted, err := privateKey.DecryptSymmetric(encrypted)
	assert.NoError(err)
	assert.EqualValues(message, string(decrypted))
}

func Test_ECIESEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)

	privateKey, err := NewRandomPrivateKey()
	assert.NoError(err)

	//k := ecies.NewPrivateKeyFromBytes(privateKey.Secret().Bytes())

	message := "super secret message"
	encrypted, err := privateKey.PublicKey().EncryptECIES([]byte(message))
	assert.NoError(err)

	decrypted, err := privateKey.DecryptECIES(encrypted)
	assert.NoError(err)

	assert.Equal(message, string(decrypted))
}
