package enc

import (
	"fmt"
	"io"
	"strings"
)

var saesSBox = [16]uint8{0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7}

var saesInverseSBox = func() (inverse [16]uint8) {
	for i, value := range saesSBox {
		inverse[value] = uint8(i)
	}
	return inverse
}()

func SAESEncrypt(key, plaintext uint16) uint16 {
	return saesEncrypt(saesExpandKey(key), plaintext, nil)
}

func SAESDecrypt(key, ciphertext uint16) uint16 {
	return saesDecrypt(saesExpandKey(key), ciphertext, nil)
}

type saesTrace func(step string, before, after uint16)

func saesExpandKey(key uint16) [3]uint16 {
	w0, w1 := uint8(key>>8), uint8(key)
	w2 := w0 ^ saesSubByte(saesRotNib(w1)) ^ 0x80
	w3 := w2 ^ w1
	w4 := w2 ^ saesSubByte(saesRotNib(w3)) ^ 0x30
	w5 := w4 ^ w3
	return [3]uint16{key, uint16(w2)<<8 | uint16(w3), uint16(w4)<<8 | uint16(w5)}
}

func saesRotNib(word uint8) uint8 { return word<<4 | word>>4 }

func saesSubByte(word uint8) uint8 {
	return saesSBox[word>>4]<<4 | saesSBox[word&0xf]
}

func saesNibbles(word uint16) [4]uint8 {
	return [4]uint8{uint8(word >> 12), uint8(word>>8) & 0xf, uint8(word>>4) & 0xf, uint8(word) & 0xf}
}

func saesWord(n [4]uint8) uint16 {
	return uint16(n[0])<<12 | uint16(n[1])<<8 | uint16(n[2])<<4 | uint16(n[3])
}

func saesSubNibs(state uint16, box [16]uint8) uint16 {
	n := saesNibbles(state)
	for i := range n {
		n[i] = box[n[i]]
	}
	return saesWord(n)
}

func saesShiftRows(state uint16) uint16 {
	n := saesNibbles(state)
	n[1], n[3] = n[3], n[1]
	return saesWord(n)
}

func saesMultiply(a, b uint8) (product uint8) {
	for range 4 {
		if b&1 != 0 {
			product ^= a
		}
		a <<= 1
		if a&0x10 != 0 {
			a ^= 0x13
		}
		b >>= 1
	}
	return product
}

func saesMixColumns(state uint16, inverse bool) uint16 {
	n := saesNibbles(state)
	a, b := uint8(1), uint8(4)
	if inverse {
		a, b = 9, 2
	}
	for i := 0; i < 4; i += 2 {
		x, y := n[i], n[i+1]
		n[i] = saesMultiply(a, x) ^ saesMultiply(b, y)
		n[i+1] = saesMultiply(b, x) ^ saesMultiply(a, y)
	}
	return saesWord(n)
}

func saesEncrypt(keys [3]uint16, plaintext uint16, trace saesTrace) uint16 {
	state := plaintext
	apply := func(step string, next uint16) {
		before := state
		state = next
		if trace != nil {
			trace(step, before, state)
		}
	}
	apply("Initial AddRoundKey(K0)", state^keys[0])
	apply("Round 1 SubNib", saesSubNibs(state, saesSBox))
	apply("Round 1 ShiftRows", saesShiftRows(state))
	apply("Round 1 MixColumns", saesMixColumns(state, false))
	apply("Round 1 AddRoundKey(K1)", state^keys[1])
	apply("Round 2 SubNib", saesSubNibs(state, saesSBox))
	apply("Round 2 ShiftRows", saesShiftRows(state))
	apply("Round 2 AddRoundKey(K2)", state^keys[2])
	return state
}

func saesDecrypt(keys [3]uint16, ciphertext uint16, trace saesTrace) uint16 {
	state := ciphertext
	apply := func(step string, next uint16) {
		before := state
		state = next
		if trace != nil {
			trace(step, before, state)
		}
	}
	apply("Initial AddRoundKey(K2)", state^keys[2])
	apply("Inverse round 1 InvShiftRows", saesShiftRows(state))
	apply("Inverse round 1 InvSubNib", saesSubNibs(state, saesInverseSBox))
	apply("Inverse round 1 AddRoundKey(K1)", state^keys[1])
	apply("Inverse round 1 InvMixColumns", saesMixColumns(state, true))
	apply("Inverse round 2 InvShiftRows", saesShiftRows(state))
	apply("Inverse round 2 InvSubNib", saesSubNibs(state, saesInverseSBox))
	apply("Inverse round 2 AddRoundKey(K0)", state^keys[0])
	return state
}

func WriteSAESTrace(w io.Writer, key, plaintext uint16) error {
	var writeErr error
	print := func(format string, args ...any) {
		if writeErr == nil {
			_, writeErr = fmt.Fprintf(w, format, args...)
		}
	}
	state := func(label string, value uint16) {
		n := saesNibbles(value)
		print("  %-30s %04X  %016b\n    [%X %X]\n    [%X %X]\n", label, value, value, n[0], n[2], n[1], n[3])
	}
	print("S-AES: 16-bit block, 16-bit key, two rounds\nState layout: 0xABCD -> [A C; B D] (column-major)\nGF(2^4) reduction polynomial: x^4 + x + 1\n\nInput\n")
	state("Plaintext", plaintext)
	state("Key", key)
	for _, box := range []struct {
		name   string
		values [16]uint8
	}{{"S-box", saesSBox}, {"Inverse S-box", saesInverseSBox}} {
		print("\n%s (index = input nibble, value = output nibble)\n  input: ", box.name)
		for i := range 16 {
			print("%X ", i)
		}
		print("\n  value: ")
		for _, value := range box.values {
			print("%X ", value)
		}
		print("\n")
	}
	keys := saesExpandKey(key)
	words := [6]uint8{uint8(key >> 8), uint8(key), uint8(keys[1] >> 8), uint8(keys[1]), uint8(keys[2] >> 8), uint8(keys[2])}
	print("\nKey expansion\n  w0 = %02X (%08b)\n  w1 = %02X (%08b)\n", words[0], words[0], words[1], words[1])
	for round, rcon := range []uint8{0x80, 0x30} {
		i := 2 + 2*round
		rot := saesRotNib(words[i-1])
		sub := saesSubByte(rot)
		print("  RotNib(w%d=%02X) = %02X\n  SubNib(%02X) = %02X\n  Rcon%d = %02X\n", i-1, words[i-1], rot, rot, sub, round+1, rcon)
		print("  w%d = w%d XOR SubNib(RotNib(w%d)) XOR Rcon%d\n     = %02X XOR %02X XOR %02X = %02X (%08b)\n", i, i-2, i-1, round+1, words[i-2], sub, rcon, words[i], words[i])
		print("  w%d = w%d XOR w%d = %02X XOR %02X = %02X (%08b)\n", i+1, i, i-1, words[i], words[i-1], words[i+1], words[i+1])
	}
	for i, k := range keys {
		state(fmt.Sprintf("K%d = w%d || w%d", i, i*2, i*2+1), k)
	}
	trace := func(step string, before, after uint16) {
		print("\n%s\n", step)
		if strings.Contains(step, "AddRoundKey") {
			print("  %04X XOR %04X = %04X\n", before, before^after, after)
		}
		if strings.HasSuffix(step, "SubNib") {
			in, out := saesNibbles(before), saesNibbles(after)
			for i := range in {
				print("  nibble %d: %X (%04b) -> %X (%04b)\n", i, in[i], in[i], out[i], out[i])
			}
		}
		if strings.HasSuffix(step, "MixColumns") {
			n := saesNibbles(before)
			a, b := uint8(1), uint8(4)
			if strings.Contains(step, "InvMixColumns") {
				a, b = 9, 2
			}
			print("  Matrix: [%X %X; %X %X], arithmetic in GF(2^4)\n", a, b, b, a)
			for i := 0; i < 4; i += 2 {
				x, y := n[i], n[i+1]
				print("  column %d top:    (%X * %X) XOR (%X * %X) = %X XOR %X = %X\n", i/2, a, x, b, y, saesMultiply(a, x), saesMultiply(b, y), saesMultiply(a, x)^saesMultiply(b, y))
				print("  column %d bottom: (%X * %X) XOR (%X * %X) = %X XOR %X = %X\n", i/2, b, x, a, y, saesMultiply(b, x), saesMultiply(a, y), saesMultiply(b, x)^saesMultiply(a, y))
			}
		}
		state("State", after)
	}
	print("\nEncryption\n")
	ciphertext := saesEncrypt(keys, plaintext, trace)
	print("\nCiphertext: %04X (%016b)\n\nDecryption\n", ciphertext, ciphertext)
	recovered := saesDecrypt(keys, ciphertext, trace)
	print("\nRecovered plaintext: %04X (%016b)\n", recovered, recovered)
	if recovered != plaintext {
		return fmt.Errorf("s-aes: round-trip verification failed")
	}
	print("Matches original: PASS\n")
	return writeErr
}
