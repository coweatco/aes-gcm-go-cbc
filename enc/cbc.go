package enc

import (
	"errors"
	"fmt"
	"io"
)

func validateCBCInputs(key, iv []byte) error {
	if len(key) != 32 {
		return errors.New("aes256cbc: key must contain exactly 32 bytes")
	}
	if len(iv) != aesBlockSize {
		return errors.New("aes256cbc: IV must contain exactly 16 bytes")
	}
	return nil
}

// AES256CBCEncrypt encrypts using PKCS#7 padding and a caller-supplied 16-byte
// IV. Use a fresh unpredictable IV for each encryption. The IV is separate from
// the returned ciphertext. Inputs are not modified. CBC provides no authentication.
func AES256CBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	if err := validateCBCInputs(key, iv); err != nil {
		return nil, err
	}
	padded, err := padPKCS7(plaintext)
	if err != nil {
		return nil, err
	}
	rk := expandKey(key)
	ciphertext := make([]byte, len(padded))
	previous := iv
	var input [aesBlockSize]byte
	// Encryption is sequential: each block depends on the preceding ciphertext.
	for offset := 0; offset < len(padded); offset += aesBlockSize {
		for i := range input {
			input[i] = padded[offset+i] ^ previous[i]
		}
		copy(ciphertext[offset:offset+aesBlockSize], aes256EncryptBlock(rk, input[:]))
		previous = ciphertext[offset : offset+aesBlockSize]
	}
	return ciphertext, nil
}

// AES256CBCDecrypt decrypts and validates PKCS#7 padding. AES block decryptions
// use bounded parallel workers, then each block is XORed with the IV or preceding
// ciphertext. Invalid padding returns nil and ErrInvalidPadding; valid padding
// does not authenticate the message. Inputs are not modified.
func AES256CBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if err := validateCBCInputs(key, iv); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aesBlockSize != 0 {
		return nil, errors.New("aes256cbc: ciphertext must be a nonempty multiple of 16 bytes")
	}
	plaintext := ecbCrypt(expandKey(key), ciphertext, aes256DecryptBlock)
	previous := iv
	for offset := 0; offset < len(plaintext); offset += aesBlockSize {
		for i := range aesBlockSize {
			plaintext[offset+i] ^= previous[i]
		}
		previous = ciphertext[offset : offset+aesBlockSize]
	}
	return unpadPKCS7(plaintext)
}

// WriteCBCTrace prints round keys, PKCS#7 padding, the IV, CBC chaining/XOR for
// up to two blocks, and every AES transformation for the first block. State bytes
// are column-major, matching the ECB/GCM traces. Output is bounded for files.
func WriteCBCTrace(w io.Writer, key, iv, plaintext []byte) error {
	if err := validateCBCInputs(key, iv); err != nil {
		return err
	}
	padded, err := padPKCS7(plaintext)
	if err != nil {
		return err
	}
	var writeErr error
	print := func(format string, args ...any) {
		if writeErr == nil {
			_, writeErr = fmt.Fprintf(w, format, args...)
		}
	}
	rk := expandKey(key)
	print("\nAES-256 round keys (hex):\n")
	for round := 0; round <= 14; round++ {
		print("  K[%02d] = %x\n", round, rk[round*16:(round+1)*16])
	}
	print("\nCBC intermediates (hex):\n  IV = %x\n  PKCS#7 padding bytes = %d\n  C[i] = AES(K, P[i] XOR chain[i]); chain[0] = IV, chain[i] = C[i-1]\n", iv, len(padded)-len(plaintext))
	previous := iv
	blocks := len(padded) / aesBlockSize
	for block := 0; block < min(2, blocks); block++ {
		p := padded[block*aesBlockSize : (block+1)*aesBlockSize]
		var input [aesBlockSize]byte
		for i := range input {
			input[i] = p[i] ^ previous[i]
		}
		print("\n  Block %d\n  P[%d] (padded) = %x\n  chain[%d] = %x\n  XOR input[%d] = %x\n", block, block, p, block, previous, block, input)
		var ct []byte
		if block == 0 {
			print("\nAES steps for first XOR input (column-major state):\n")
			ct = aes256EncryptBlockTrace(rk, input[:], func(round int, step string, state []byte) {
				print("  Round %02d %-12s %x\n", round, step, state)
			})
		} else {
			ct = aes256EncryptBlock(rk, input[:])
		}
		print("  C[%d] = %x\n", block, ct)
		decoded := aes256DecryptBlock(rk, ct)
		var recovered [aesBlockSize]byte
		for i := range recovered {
			recovered[i] = decoded[i] ^ previous[i]
		}
		print("  AES^-1(K, C[%d]) = %x\n  Recovered padded P[%d] = AES^-1(K, C[%d]) XOR chain[%d] = %x\n", block, decoded, block, block, block, recovered)
		previous = ct
	}
	if blocks > 2 {
		print("\n  Showing first 2 of %d padded blocks.\n", blocks)
	}
	return writeErr
}
