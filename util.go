package easyecc

import "encoding/base64"

func base64urlEncode(data []byte) string {
	return base64.StdEncoding.
		WithPadding(base64.NoPadding).
		EncodeToString(data)
}

func base64urlDecode(s string) ([]byte, error) {
	return base64.
		StdEncoding.WithPadding(base64.NoPadding).
		DecodeString(s)
}

func padWithZeros(b []byte, l int) []byte {
	for len(b) < l {
		b = append([]byte{0}, b...)
	}
	return b
}
