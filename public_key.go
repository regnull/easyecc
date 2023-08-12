package easyecc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
)

// PublicKey represents elliptic curve cryptography private key.
type PublicKey struct {
	publicKey *ecdsa.PublicKey
}

// We must deal with secp256k1 here, because elliptic UnmarshalCompressed cannot handle it.
func unmarshalCompressedSECP256K1(serialized []byte) (*PublicKey, error) {
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

func NewPublicKeyFromBytes(curve EllipticCurve, b []byte) (*PublicKey, error) {
	x, y := elliptic.Unmarshal(getCurve(curve), b)
	return &PublicKey{publicKey: &ecdsa.PublicKey{
		Curve: getCurve(curve),
		X:     x,
		Y:     y}}, nil
}

func NewPublicKeyFromCompressedBytes(curve EllipticCurve, b []byte) (*PublicKey, error) {
	if curve == SECP256K1 {
		// Special case - elliptic.UnmarshalCompressed cannot handle it.
		return unmarshalCompressedSECP256K1(b)
	}
	x, y := elliptic.UnmarshalCompressed(getCurve(curve), b)
	return &PublicKey{publicKey: &ecdsa.PublicKey{
		Curve: getCurve(curve),
		X:     x,
		Y:     y}}, nil
}

func (pbk *PublicKey) Bytes() []byte {
	return elliptic.Marshal(pbk.publicKey.Curve, pbk.publicKey.X, pbk.publicKey.Y)
}

// SerializeCompressed returns the private key serialized in SEC compressed format. The result
// is 33 bytes long.
func (pbk *PublicKey) CompressedBytes() []byte {
	return elliptic.MarshalCompressed(pbk.publicKey.Curve, pbk.publicKey.X, pbk.publicKey.Y)
}

// Curve returns the elliptic curve for this public key.
func (pbk *PublicKey) Curve() EllipticCurve {
	if pbk.publicKey.Curve == btcec.S256() {
		return SECP256K1
	}
	if pbk.publicKey.Curve == elliptic.P256() {
		return P256
	}
	if pbk.publicKey.Curve == elliptic.P384() {
		return P384
	}
	if pbk.publicKey.Curve == elliptic.P521() {
		return P521
	}
	return -1
}

// X returns X component of the public key.
func (pbk *PublicKey) X() *big.Int {
	return pbk.publicKey.X
}

// Y returns Y component of the public key.
func (pbk *PublicKey) Y() *big.Int {
	return pbk.publicKey.Y
}

// BitcoinAddress returns the Bitcoin address for this public key.
// Unless the public key is on SECP256K1 curve, ErrUnsupportedCurve is returned.
func (pbk *PublicKey) BitcoinAddress() (string, error) {
	if pbk.Curve() != SECP256K1 {
		return "", ErrUnsupportedCurve
	}
	prefix := []byte{0x00}
	s := pbk.CompressedBytes()
	hash := Hash160(s)
	s1 := bytes.Join([][]byte{prefix, hash}, nil)
	checkSum := Hash256(s1)[0:4]
	addr := bytes.Join([][]byte{s1, checkSum}, nil)
	return base58.Encode(addr), nil
}

// EthereumAddress returns an Ethereum address for this public key.
// Unless the public key is on SECP256K1 curve, ErrUnsupportedCurve is returned.
func (pbk *PublicKey) EthereumAddress() (string, error) {
	if pbk.Curve() != SECP256K1 {
		return "", ErrUnsupportedCurve
	}
	return crypto.PubkeyToAddress(*pbk.publicKey).Hex(), nil
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
	return bytes.Equal(pbk.CompressedBytes(), other)
}

// ToECDSA returns this key as crypto/ecdsa public key.
func (pbk *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return pbk.publicKey
}
