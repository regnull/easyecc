package easyecc

// GetPlainTextLength returns plain text length for the given ciphertext.
// The ciphertext is assumed to be obtained by calling PrivateKey.Encrypt().
func GetPlainTextLength(cipherTextLength int) int {
	// This is very unscientific.
	if cipherTextLength < 28 {
		return 0
	}
	return cipherTextLength - 28
}

// SerializedCompressedToAddress is a convenience function which converts
// serialized compressed representation of the private key to its address (which is shorter).
// If the key is invalid, the return string will contain an error message.
func SerializedCompressedToAddress(key []byte) string {
	publicKey, err := NewPublicFromSerializedCompressed(key)
	if err != nil {
		return "**invalid key**"
	}
	address, _ := publicKey.BitcoinAddress()
	return address
}
