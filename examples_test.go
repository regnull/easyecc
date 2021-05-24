package easyecc

import (
	"fmt"
	"log"
	"math/big"
)

func Example_SignAndVerify() {
	privateKey := NewPrivateKey(big.NewInt(12345))
	data := "super secret message"
	hash := Hash256([]byte(data))
	signature, err := privateKey.Sign(hash)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.PublicKey()
	success := signature.Verify(publicKey, hash)
	fmt.Printf("Signature verified: %v\n", success)
	// Output: Signature verified: true
}
