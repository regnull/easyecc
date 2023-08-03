package easyecc

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

var serializedKeys = map[EllipticCurve]string{
	SECP256K1: "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1",
	P256:      "035959f21263a385367a2737020e9c912f7ec94a1c7f535bb104d8be472728bb84",
	P384:      "0283a4f85dbb29ffd415547c8f88924d2dc7d5c2e7ac371fded2360e645e142534d924d5fc7182298ae78e43dc042e3185",
	P521:      "02014f3231b54b107be2ed7ec03dd85e2169111a087bb29454200a06f2e470ef5060f97c255ce621a771c1689a4defafa057ae100c1552428de87c757510a71271b5cb",
}

type keyComponents struct {
	X string
	Y string
}

var serializedKeyComponents = map[EllipticCurve]keyComponents{
	SECP256K1: {
		X: "57a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1",
		Y: "0d6cc87c5bc29b83368e17869e964f2f53d52ea3aa3e5a9efa1fa578123a0c6d",
	},
	P256: {
		X: "5959f21263a385367a2737020e9c912f7ec94a1c7f535bb104d8be472728bb84",
		Y: "669f338928b52ac42850f2444d1c1bf4db10e21a21151b39c126ed88ca1b93f5",
	},
	P384: {
		X: "83a4f85dbb29ffd415547c8f88924d2dc7d5c2e7ac371fded2360e645e142534d924d5fc7182298ae78e43dc042e3185",
		Y: "28cac85e8ab852371b3481ef26c3a08c7ab6834fca48b3238c80d924a79d8c2f3b1c2b54c8e2d949a77f6ce7f579bb08",
	},
	P521: {
		X: "14f3231b54b107be2ed7ec03dd85e2169111a087bb29454200a06f2e470ef5060f97c255ce621a771c1689a4defafa057ae100c1552428de87c757510a71271b5cb",
		Y: "172092d6462143a95cdbbb08dc1b2c464ce7ff915036cb9c844323e8c88cee4f4bc16d8bfbfafe3f3c1871373351bc69b46f541745d8acb5c66d3c24e70fde428a4",
	},
}

func Test_PublicKey_SerializeCompressed(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		privateKey := CreatePrivateKey(curve, big.NewInt(5001))
		publicKey := privateKey.PublicKey()
		serialized := publicKey.SerializeCompressed()
		assert.EqualValues(serializedKeys[curve], fmt.Sprintf("%x", serialized))
		assert.True(true)
	}
}

func Test_PublicKey_Curve(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		privateKey := CreatePrivateKey(curve, big.NewInt(5001))
		publicKey := privateKey.PublicKey()
		assert.Equal(curve, publicKey.Curve())
	}
}

func Test_PublicKey_FromSerializedCompressed(t *testing.T) {
	assert := assert.New(t)

	for _, curve := range curves {
		serialized, _ := new(big.Int).SetString(serializedKeys[curve], 16)
		publicKey, err := DeserializeCompressed(curve, serialized.Bytes())
		assert.NoError(err)
		assert.NotNil(publicKey)
		assert.EqualValues(serializedKeyComponents[curve].X, fmt.Sprintf("%064x", publicKey.publicKey.X))
		assert.EqualValues(serializedKeyComponents[curve].Y, fmt.Sprintf("%064x", publicKey.publicKey.Y))
	}
}

func Test_PublicKey_Address(t *testing.T) {
	assert := assert.New(t)

	secret, _ := new(big.Int).SetString("12345deadbeef", 16)
	privateKey := NewPrivateKey(secret)
	address, err := privateKey.PublicKey().BitcoinAddress()
	assert.NoError(err)
	assert.Equal("1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1", address)
}

func Test_PublicKey_Equal(t *testing.T) {
	assert := assert.New(t)

	privateKey1, err := NewRandomPrivateKey()
	assert.NoError(err)
	publicKey1 := privateKey1.PublicKey()
	publicKey2, err := NewPublicFromSerializedCompressed(publicKey1.SerializeCompressed())
	assert.NoError(err)

	assert.True(publicKey1.Equal(publicKey2))
	assert.True(publicKey1.EqualSerializedCompressed(publicKey2.SerializeCompressed()))

	privateKey3, err := NewRandomPrivateKey()
	assert.NoError(err)
	publicKey3 := privateKey3.PublicKey()

	assert.False(publicKey1.Equal(publicKey3))
	assert.False(publicKey1.EqualSerializedCompressed(publicKey3.SerializeCompressed()))
}

func Test_PublicKey_SerializeSECP256K1(t *testing.T) {
	assert := assert.New(t)

	key, err := GeneratePrivateKey(SECP256K1)
	assert.NoError(err)

	b := key.PublicKey().Serialize()
	assert.True(len(b) > 0)

	publicKey, err := Deserialize(SECP256K1, b)
	assert.NoError(err)

	assert.True(publicKey.Equal(key.PublicKey()))
}
