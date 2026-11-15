package enc

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"
)

const aesBlockSize = 16

var aesInverseSBox = func() (inverse [256]byte) {
	for i, value := range AES_S_BOX {
		inverse[value] = byte(i)
	}
	return inverse
}()

// WriteECBTrace exposes round keys and AES states for the first padded plaintext
// block. Only that block is expanded, keeping file inspection output bounded.
func WriteECBTrace(w io.Writer, key, plaintext []byte) error {
	if len(key) != 32 {
		return errors.New("aes256ecb: key must contain exactly 32 bytes")
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
	padding := aesBlockSize - len(plaintext)%aesBlockSize
	var first [aesBlockSize]byte
	n := copy(first[:], plaintext)
	for i := n; i < aesBlockSize; i++ {
		first[i] = byte(padding)
	}
	print("\nECB intermediates (hex):\n  PKCS#7 padding bytes = %d\n  First padded plaintext block = %x\n\nAES steps for first plaintext block (column-major state):\n", padding, first)
	ct := aes256EncryptBlockTrace(rk, first[:], func(round int, step string, state []byte) {
		print("  Round %02d %-12s %x\n", round, step, state)
	})
	print("\n  First ciphertext block = %x\n", ct)
	return writeErr
}

// AES256ECBEncrypt encrypts with a 32-byte key and PKCS#7 padding. Empty and
// block-aligned messages receive a full padding block. Inputs are not modified.
// ECB reveals repeated plaintext blocks and provides no authentication.
func AES256ECBEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("aes256ecb: key must contain exactly 32 bytes")
	}
	padded, err := padPKCS7(plaintext)
	if err != nil {
		return nil, err
	}
	return ecbCrypt(expandKey(key), padded, aes256EncryptBlock), nil
}

// AES256ECBDecrypt decrypts nonempty, block-aligned ciphertext and removes
// PKCS#7 padding. Invalid padding returns nil plaintext and ErrInvalidPadding.
// Successful padding validation does not authenticate the ciphertext.
func AES256ECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("aes256ecb: key must contain exactly 32 bytes")
	}
	if len(ciphertext) == 0 || len(ciphertext)%aesBlockSize != 0 {
		return nil, errors.New("aes256ecb: ciphertext must be a nonempty multiple of 16 bytes")
	}
	plaintext := ecbCrypt(expandKey(key), ciphertext, aes256DecryptBlock)
	return unpadPKCS7(plaintext)
}

// ecbCrypt assigns disjoint block ranges to a bounded number of workers.
func ecbCrypt(rk, input []byte, block func([]byte, []byte) []byte) []byte {
	output := make([]byte, len(input))
	cryptRange := func(start, end int) {
		for offset := start; offset < end; offset += aesBlockSize {
			copy(output[offset:offset+aesBlockSize], block(rk, input[offset:offset+aesBlockSize]))
		}
	}
	workers := min(runtime.GOMAXPROCS(0), len(input)/(16*1024))
	if workers < 2 {
		cryptRange(0, len(input))
		return output
	}
	blocks := len(input) / aesBlockSize
	perWorker, extra := blocks/workers, blocks%workers
	var wg sync.WaitGroup
	start := 0
	for worker := 0; worker < workers; worker++ {
		count := perWorker
		if worker < extra {
			count++
		}
		end := start + count*aesBlockSize
		wg.Add(1)
		go func(start, end int) { defer wg.Done(); cryptRange(start, end) }(start, end)
		start = end
	}
	wg.Wait()
	return output
}

func aes256DecryptBlock(rk, data []byte) []byte {
	state := slices.Clone(data)
	addRoundKey(state, rk[14*16:15*16])
	for round := 13; round >= 1; round-- {
		inverseShiftRows(state)
		inverseSubBytes(state)
		addRoundKey(state, rk[round*16:(round+1)*16])
		inverseMixColumns(state)
	}
	inverseShiftRows(state)
	inverseSubBytes(state)
	addRoundKey(state, rk[:16])
	return state
}

func inverseShiftRows(state []byte) {
	state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
	state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
}

func inverseSubBytes(state []byte) {
	for i := range state {
		state[i] = aesInverseSBox[state[i]]
	}
}

func inverseMixColumns(state []byte) {
	// Preconditioning followed by MixColumns equals multiplication by the
	// inverse matrix with coefficients 0e, 0b, 0d and 09 in GF(2^8).
	for i := 0; i < aesBlockSize; i += 4 {
		u := xtime(xtime(state[i] ^ state[i+2]))
		v := xtime(xtime(state[i+1] ^ state[i+3]))
		state[i] ^= u
		state[i+2] ^= u
		state[i+1] ^= v
		state[i+3] ^= v
	}
	mixColumns(state)
}
