package easyecc

import (
	"fmt"
	"log"
	"math/big"
)

func ExamplePrivateKey_Sign() {
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

func ExamplePrivateKey_Encrypt() {
	aliceKey, err := NewRandomPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	bobKey, err := NewRandomPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	data := "super secret message"
	encrypted, err := aliceKey.Encrypt([]byte(data), bobKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := bobKey.Decrypt(encrypted, aliceKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(decrypted))
	// Output: super secret message
}

func ExamplePrivateKey_EncryptKeyWithPassphrase() {
	privateKey := NewPrivateKey(big.NewInt(12345))
	encryptedKey, err := privateKey.EncryptKeyWithPassphrase("my passphrase")
	if err != nil {
		log.Fatal(err)
	}
	decryptedKey, err := NewPrivateKeyFromEncryptedWithPassphrase(encryptedKey, "my passphrase")
	fmt.Printf("%d\n", decryptedKey.Secret())
	// Output: 12345
}

func ExamplePublicKey_SerializeCompressed() {
	privateKey := NewPrivateKey(big.NewInt(12345))
	publicKey := privateKey.PublicKey()
	serializedCompressed := publicKey.SerializeCompressed()
	fmt.Printf("%x\n", serializedCompressed)
	publicKeyCopy, err := NewPublicFromSerializedCompressed(serializedCompressed)
	if err != nil {
		log.Fatal(err)
	}
	sameKey := publicKey.Equal(publicKeyCopy)
	fmt.Printf("the correct key was created: %v\n", sameKey)
	// Output: 03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f
	// the correct key was created: true
}
