package enc

import (
	"crypto/subtle"
	"errors"
)

var ErrInvalidPadding = errors.New("aes: invalid PKCS#7 padding")

func padPKCS7(plaintext []byte) ([]byte, error) {
	padding := aesBlockSize - len(plaintext)%aesBlockSize
	if len(plaintext) > int(^uint(0)>>1)-padding {
		return nil, errors.New("aes: plaintext is too large")
	}
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded, nil
}

func unpadPKCS7(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%aesBlockSize != 0 {
		return nil, ErrInvalidPadding
	}
	padding := int(plaintext[len(plaintext)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, aesBlockSize)
	for i := 1; i <= aesBlockSize; i++ {
		inPadding := subtle.ConstantTimeLessOrEq(i, padding)
		matches := subtle.ConstantTimeByteEq(plaintext[len(plaintext)-i], byte(padding))
		valid &= 1 ^ (inPadding & (1 ^ matches))
	}
	if valid != 1 {
		return nil, ErrInvalidPadding
	}
	return plaintext[:len(plaintext)-padding], nil
}
