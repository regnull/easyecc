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
