package easyecc

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	ecies "github.com/ecies/go"
	"github.com/ethereum/go-ethereum/crypto"
)

// PublicKey represents elliptic curve cryptography private key.
type PublicKey struct {
	publicKey *ecdsa.PublicKey
}

// NewPublicFromSerializedCompressed creates new public key from serialized
// compressed format.
func NewPublicFromSerializedCompressed(serialized []byte) (*PublicKey, error) {
	if len(serialized) != 33 {
		return nil, fmt.Errorf("invalid serialized compressed public key")
	}

	even := false
	if serialized[0] == 0x02 {
		even = true
	} else if serialized[0] == 0x03 {
		even = false
	} else {
		return nil, fmt.Errorf("invalid serialized compressed public key")
	}
	x := new(big.Int).SetBytes(serialized[1:])
	P := btcec.S256().CurveParams.P
	sqrtExp := new(big.Int).Add(P, big.NewInt(1))
	sqrtExp = sqrtExp.Div(sqrtExp, big.NewInt(4))
	alpha := new(big.Int).Exp(x, big.NewInt(3), P)
	alpha.Add(alpha, btcec.S256().B)
	beta := new(big.Int).Exp(alpha, sqrtExp, P)
	var evenBeta *big.Int
	var oddBeta *big.Int
	if new(big.Int).Mod(beta, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		evenBeta = beta
		oddBeta = new(big.Int).Sub(P, beta)
	} else {
		evenBeta = new(big.Int).Sub(P, beta)
		oddBeta = beta
	}
	var y *big.Int
	if even {
		y = evenBeta
	} else {
		y = oddBeta
	}
	return &PublicKey{publicKey: &ecdsa.PublicKey{
		Curve: btcec.S256(),
		X:     x,
		Y:     y}}, nil
}

// SerializeCompressed returns the private key serialized in SEC compressed format. The result
// is 33 bytes long.
func (pbk *PublicKey) SerializeCompressed() []byte {
	buf := make([]byte, 33)
	if new(big.Int).Mod(pbk.publicKey.Y, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		// Even.
		buf[0] = 0x02
	} else {
		// Odd.
		buf[0] = 0x03
	}

	yBytes := pbk.publicKey.X.Bytes()

	// If lengths of yBytes happens to be less then 32, pad it with zero bytes on the left.
	if len(yBytes) < 32 {
		yBytes = bytes.Join([][]byte{make([]byte, 32-len(yBytes)), yBytes}, nil)
	}

	for i := 1; i < 33; i++ {
		buf[i] = yBytes[i-1]
	}
	return buf
}

// X returns X component of the public key.
func (pbk *PublicKey) X() *big.Int {
	return pbk.publicKey.X
}

// Y returns Y component of the public key.
func (pbk *PublicKey) Y() *big.Int {
	return pbk.publicKey.Y
}

// Address returns Bitcoin address associated with this private key.
func (pbk *PublicKey) Address() string {
	prefix := []byte{0x00}
	s := pbk.SerializeCompressed()
	hash := Hash160(s)
	s1 := bytes.Join([][]byte{prefix, hash}, nil)
	checkSum := Hash256(s1)[0:4]
	addr := bytes.Join([][]byte{s1, checkSum}, nil)
	return base58.Encode(addr)
}

// EthereumAddress returns an Ethereum address for this public key.
func (pbk *PublicKey) EthereumAddress() string {
	return crypto.PubkeyToAddress(*pbk.publicKey).Hex()
}

// Equal returns true if this key is equal to the other key.
func (pbk *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return pbk.publicKey.X.Cmp(other.publicKey.X) == 0 &&
		pbk.publicKey.Y.Cmp(other.publicKey.Y) == 0
}

// EqualSerializedCompressed returns true if this key is equal to the other,
// given as serialized compressed representation.
func (pbk *PublicKey) EqualSerializedCompressed(other []byte) bool {
	return bytes.Equal(pbk.SerializeCompressed(), other)
}

// ToECDSA returns this key as crypto/ecdsa public key.
func (pbk *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return pbk.publicKey
}

// EncryptECIES encrypts plaintext using Elliptic Curve Integrated Encryption Scheme.
// See https://cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme
func (pbk *PublicKey) EncryptECIES(plaintext []byte) ([]byte, error) {
	k, err := ecies.NewPublicKeyFromBytes(pbk.SerializeCompressed())
	if err != nil {
		return nil, err
	}
	return ecies.Encrypt(k, plaintext)
}
