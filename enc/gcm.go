package enc

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"
)

var AES_RCON = []byte{
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
}

var AES_S_BOX = []byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

func subWord(word []byte) []byte {
	if len(word) == 0 {
		return word
	}

	ret := make([]byte, len(word))

	for i := range word {
		ret[i] = AES_S_BOX[word[i]]
	}

	return ret
}

func rotWord(word []byte) []byte {
	if len(word) != 4 {
		panic("rotWord: word must contain exactly 4 bytes")
	}

	return []byte{word[1], word[2], word[3], word[0]}
}

func xorWords(a, b []byte) []byte {
	if len(a) != 4 || len(b) != 4 {
		panic("xorWords: both words must contain exactly 4 bytes")
	}

	ret := make([]byte, 4)

	for i := range ret {
		ret[i] = a[i] ^ b[i]
	}

	return ret
}

func expandKey(key []byte) []byte {
	if len(key) != 32 {
		panic("expandKey: AES-256 requires a 32-byte key")
	}

	const wordBytes = 4
	const wordCount = 60

	words := make([][]byte, wordCount)

	for i := range 8 {
		start := i * wordBytes
		words[i] = key[start : start+wordBytes]
	}

	for i := 8; i <= 59; i++ {
		temp := words[i-1]

		switch i % 8 {
		case 0:
			temp = subWord(rotWord(temp))
			temp[0] ^= AES_RCON[i/8]
		case 4:
			temp = subWord(temp)
		}

		words[i] = xorWords(words[i-8], temp)
	}

	roundKeys := make([]byte, 60*4)

	for i, word := range words {
		copy(roundKeys[i*4:(i+1)*4], word)
	}

	return roundKeys
}

func addRoundKey(state, roundKey []byte) {
	if len(state) != 16 || len(roundKey) != 16 {
		panic("addRoundKey: state and round key must each contain 16 bytes")
	}

	for i := range state {
		state[i] ^= roundKey[i]
	}
}

func xtime(x byte) byte {
	if x&0x80 != 0 {
		return (x << 1) ^ 0x1b
	}
	return x << 1
}

func mixColumns(state []byte) {
	if len(state) != 16 {
		panic("mixColumns: state must contain exactly 16 bytes")
	}

	for i := 0; i < 16; i += 4 {
		a, b, c, d := state[i], state[i+1], state[i+2], state[i+3]

		a2, b2, c2, d2 := xtime(a), xtime(b), xtime(c), xtime(d)

		state[i] = a2 ^ (b2 ^ b) ^ c ^ d
		state[i+1] = a ^ b2 ^ (c2 ^ c) ^ d
		state[i+2] = a ^ b ^ c2 ^ (d2 ^ d)
		state[i+3] = (a2 ^ a) ^ b ^ c ^ d2
	}
}

func shiftRows(state []byte) {
	if len(state) != 16 {
		panic("shiftRows: state must contain exactly 16 bytes")
	}

	state[1], state[5], state[9], state[13] =
		state[5], state[9], state[13], state[1]

	state[2], state[6], state[10], state[14] =
		state[10], state[14], state[2], state[6]

	state[3], state[7], state[11], state[15] =
		state[15], state[3], state[7], state[11]
}

func subBytes(state []byte) {
	if len(state) != 16 {
		panic("subBytes: state must contain exactly 16 bytes")
	}

	for i := range state {
		state[i] = AES_S_BOX[state[i]]
	}
}

func aes256EncryptBlock(rk, data []byte) []byte {
	return aes256EncryptBlockTrace(rk, data, nil)
}

func aes256EncryptBlockTrace(rk, data []byte, trace func(int, string, []byte)) []byte {
	state := slices.Clone(data)
	emit := func(round int, step string) {
		if trace != nil {
			trace(round, step, slices.Clone(state))
		}
	}
	emit(0, "Input")

	addRoundKey(state, rk[:16])
	emit(0, "AddRoundKey")

	for round := 1; round <= 13; round++ {
		subBytes(state)
		emit(round, "SubBytes")
		shiftRows(state)
		emit(round, "ShiftRows")
		mixColumns(state)
		emit(round, "MixColumns")
		addRoundKey(state, rk[round*16:(round+1)*16])
		emit(round, "AddRoundKey")
	}

	subBytes(state)
	emit(14, "SubBytes")
	shiftRows(state)
	emit(14, "ShiftRows")
	addRoundKey(state, rk[14*16:15*16])
	emit(14, "AddRoundKey")

	return state
}

const (
	GCMTagSize        = 16
	maxGCMMessageSize = (uint64(1)<<32 - 2) * 16
)

var ErrAuthentication = errors.New("aes256gcm: authentication failed")

func WriteGCMTrace(w io.Writer, key, nonce, plaintext, additionalData []byte) error {
	ct, tag, err := AES256GCMEncrypt(key, nonce, plaintext, additionalData)
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
	var h [16]byte
	copy(h[:], aes256EncryptBlock(rk, make([]byte, 16)))
	j0 := initialCounter(h, nonce)
	print("\nGCM intermediates (hex):\n  H = AES(K, 0) = %x\n  J0 = %x\n", h, j0)
	if len(plaintext) > 0 {
		counter := j0
		binary.BigEndian.PutUint32(counter[12:], binary.BigEndian.Uint32(counter[12:])+1)
		print("  First counter = %x\n\nAES steps for first counter (column-major state):\n", counter)
		stream := aes256EncryptBlockTrace(rk, counter[:], func(round int, step string, state []byte) {
			print("  Round %02d %-12s %x\n", round, step, state)
		})
		n := min(16, len(plaintext))
		print("\n  First keystream block = %x\n  Plaintext block = %x\n  Ciphertext = plaintext XOR keystream = %x\n", stream, plaintext[:n], ct[:n])
	}
	sum := ghash(h, additionalData, ct)
	mask := aes256EncryptBlock(rk, j0[:])
	print("  GHASH(AAD, ciphertext) = %x\n  AES(K, J0) = %x\n  Tag = GHASH XOR AES(K, J0) = %x\n", sum, mask, tag)
	return writeErr
}

func AES256GCMEncrypt(key, nonce, plaintext, additionalData []byte) (ciphertext, tag []byte, err error) {
	if err = validateGCMInputs(key, nonce, additionalData, len(plaintext)); err != nil {
		return nil, nil, err
	}
	rk := expandKey(key)
	var h [16]byte
	copy(h[:], aes256EncryptBlock(rk, make([]byte, 16)))
	j0 := initialCounter(h, nonce)
	ciphertext = gcmCounterCrypt(rk, j0, plaintext)
	t := gcmTag(rk, h, j0, additionalData, ciphertext)
	return ciphertext, t[:], nil
}

func AES256GCMDecrypt(key, nonce, ciphertext, additionalData, tag []byte) ([]byte, error) {
	if err := validateGCMInputs(key, nonce, additionalData, len(ciphertext)); err != nil {
		return nil, err
	}
	if len(tag) != GCMTagSize {
		return nil, ErrAuthentication
	}
	rk := expandKey(key)
	var h [16]byte
	copy(h[:], aes256EncryptBlock(rk, make([]byte, 16)))
	j0 := initialCounter(h, nonce)
	expected := gcmTag(rk, h, j0, additionalData, ciphertext)
	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		return nil, ErrAuthentication
	}
	return gcmCounterCrypt(rk, j0, ciphertext), nil
}

func validateGCMInputs(key, nonce, additionalData []byte, messageSize int) error {
	if len(key) != 32 {
		return errors.New("aes256gcm: key must contain exactly 32 bytes")
	}
	if len(nonce) == 0 {
		return errors.New("aes256gcm: nonce must not be empty")
	}
	const maxBitLengthBytes = ^uint64(0) / 8
	if uint64(len(nonce)) > maxBitLengthBytes || uint64(len(additionalData)) > maxBitLengthBytes {
		return errors.New("aes256gcm: nonce or additional data is too large")
	}
	if messageSize < 0 || uint64(messageSize) > maxGCMMessageSize {
		return errors.New("aes256gcm: message is too large")
	}
	return nil
}

func initialCounter(h [16]byte, nonce []byte) (j0 [16]byte) {
	if len(nonce) == 12 {
		copy(j0[:12], nonce)
		j0[15] = 1
		return j0
	}
	return ghash(h, nil, nonce)
}

func gcmCounterCrypt(rk []byte, counter [16]byte, input []byte) []byte {
	output := make([]byte, len(input))
	const minWorkerBytes = 16 * 1024
	workers := min(runtime.GOMAXPROCS(0), len(input)/minWorkerBytes)
	if workers < 2 {
		gcmCounterCryptRange(rk, counter, input, output, 0, len(input))
		return output
	}
	blocks := len(input) / 16
	if len(input)%16 != 0 {
		blocks++
	}
	blocksPerWorker, extra := blocks/workers, blocks%workers
	var wg sync.WaitGroup
	startBlock := 0
	for worker := range workers {
		endBlock := startBlock + blocksPerWorker
		if worker < extra {
			endBlock++
		}
		start, end := startBlock*16, len(input)
		if endBlock < blocks {
			end = endBlock * 16
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			gcmCounterCryptRange(rk, counter, input, output, start, end)
		}(start, end)
		startBlock = endBlock
	}
	wg.Wait()
	return output
}

func gcmCounterCryptRange(rk []byte, counter [16]byte, input, output []byte, start, end int) {
	binary.BigEndian.PutUint32(counter[12:], binary.BigEndian.Uint32(counter[12:])+uint32(start/16))
	for offset := start; offset < end; {
		binary.BigEndian.PutUint32(counter[12:], binary.BigEndian.Uint32(counter[12:])+1)
		stream := aes256EncryptBlock(rk, counter[:])
		n := min(16, end-offset)
		for i := range n {
			output[offset+i] = input[offset+i] ^ stream[i]
		}
		offset += n
	}
}

func gcmTag(rk []byte, h, j0 [16]byte, additionalData, ciphertext []byte) [16]byte {
	tag := ghash(h, additionalData, ciphertext)
	mask := aes256EncryptBlock(rk, j0[:])
	for i := range tag {
		tag[i] ^= mask[i]
	}
	return tag
}

func ghash(h [16]byte, additionalData, ciphertext []byte) (sum [16]byte) {
	for _, data := range [][]byte{additionalData, ciphertext} {
		for len(data) > 0 {
			n := min(16, len(data))
			for i := range n {
				sum[i] ^= data[i]
			}
			sum = gcmMultiply(sum, h)
			data = data[n:]
		}
	}
	var lengths [16]byte
	binary.BigEndian.PutUint64(lengths[:8], uint64(len(additionalData))*8)
	binary.BigEndian.PutUint64(lengths[8:], uint64(len(ciphertext))*8)
	for i := range sum {
		sum[i] ^= lengths[i]
	}
	return gcmMultiply(sum, h)
}

func gcmMultiply(x, y [16]byte) (product [16]byte) {
	v := y
	for bit := range 128 {
		mask := byte(0) - ((x[bit/8] >> (7 - uint(bit%8))) & 1)
		for i := range product {
			product[i] ^= v[i] & mask
		}
		reduction := byte(0) - (v[15] & 1)
		for i := 15; i > 0; i-- {
			v[i] = v[i]>>1 | v[i-1]<<7
		}
		v[0] = v[0]>>1 ^ (0xe1 & reduction)
	}
	return product
}
