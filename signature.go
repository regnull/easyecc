package easyecc

import (
	"crypto/ecdsa"
	"math/big"
)

// Signature represents a cryptographic signature (ECDSA).
// See https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
type Signature struct {
	R *big.Int
	S *big.Int
}

// Verify verifies the signer using the public key and the hash of the data.
func (sig *Signature) Verify(key *PublicKey, hash []byte) bool {
	return ecdsa.Verify(key.publicKey, hash, sig.R, sig.S)
}
