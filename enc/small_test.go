package enc

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSAESKnownAnswer(t *testing.T) {
	// Standard worked S-AES example: key 4AF5, plaintext D728, ciphertext 24EC.
	const key, plaintext, ciphertext = uint16(0x4af5), uint16(0xd728), uint16(0x24ec)
	if got := saesExpandKey(key); got != [3]uint16{0x4af5, 0xdd28, 0x87af} {
		t.Fatalf("round keys = %04X", got)
	}
	if got := SAESEncrypt(key, plaintext); got != ciphertext {
		t.Fatalf("encrypt = %04X, want %04X", got, ciphertext)
	}
	if got := SAESDecrypt(key, ciphertext); got != plaintext {
		t.Fatalf("decrypt = %04X, want %04X", got, plaintext)
	}
	want := []uint16{0x9ddd, 0x2eee, 0x2eee, 0xf633, 0x2b1b, 0xa343, 0xa343, 0x24ec}
	var got []uint16
	saesEncrypt(saesExpandKey(key), plaintext, func(_ string, _, after uint16) { got = append(got, after) })
	if len(got) != len(want) {
		t.Fatalf("trace has %d states", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d = %04X, want %04X", i, got[i], want[i])
		}
	}
}

func TestSAESAllPlaintexts(t *testing.T) {
	for _, key := range []uint16{0, 0x4af5, 0xffff} {
		var seen [1 << 16]bool
		for value := range 1 << 16 {
			p := uint16(value)
			ct := SAESEncrypt(key, p)
			if seen[ct] {
				t.Fatalf("ciphertext collision for key %04X", key)
			}
			seen[ct] = true
			if got := SAESDecrypt(key, ct); got != p {
				t.Fatalf("key=%04X plaintext=%04X recovered=%04X", key, p, got)
			}
		}
	}
}

func TestSAESAllKeys(t *testing.T) {
	for value := range 1 << 16 {
		key := uint16(value)
		if got := SAESDecrypt(key, SAESEncrypt(key, 0xd728)); got != 0xd728 {
			t.Fatalf("round trip failed for key %04X", key)
		}
	}
}

func TestSAESInverseTransforms(t *testing.T) {
	for value := range 1 << 16 {
		state := uint16(value)
		if got := saesMixColumns(saesMixColumns(state, false), true); got != state {
			t.Fatalf("MixColumns inverse failed for %04X", state)
		}
		if got := saesShiftRows(saesShiftRows(state)); got != state {
			t.Fatalf("ShiftRows inverse failed for %04X", state)
		}
		if got := saesSubNibs(saesSubNibs(state, saesSBox), saesInverseSBox); got != state {
			t.Fatalf("SubNib inverse failed for %04X", state)
		}
	}
}

func TestSAESTrace(t *testing.T) {
	var out bytes.Buffer
	if err := WriteSAESTrace(&out, 0x4af5, 0xd728); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"State layout: 0xABCD -> [A C; B D]", "S-box", "Inverse S-box", "Key expansion",
		"RotNib(w1=F5) = 5F", "SubNib(5F) = 17", "Rcon1 = 80", "Rcon2 = 30",
		"K1 = w2 || w3", "DD28", "K2 = w4 || w5", "87AF",
		"Round 1 MixColumns", "column 0 top:", "nibble 0:", "Inverse round 1 InvMixColumns",
		"Ciphertext: 24EC", "Recovered plaintext: D728", "Matches original: PASS",
		"[D 2]", "[7 8]", "1101011100101000",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing trace output %q", want)
		}
	}
	if strings.Contains(out.String(), "Round 2 MixColumns") {
		t.Fatal("final encryption round must omit MixColumns")
	}
	if err := WriteSAESTrace(failingWriter{}, 0x4af5, 0xd728); !errors.Is(err, errWrite) {
		t.Fatalf("writer error = %v", err)
	}
}
