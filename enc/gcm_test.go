package enc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

func TestGCMCompatibility(t *testing.T) {
	rng := rand.New(rand.NewSource(256))
	random := func(n int) []byte { b := make([]byte, n); rng.Read(b); return b }
	for _, ns := range []int{1, 8, 12, 13, 16, 31, 32, 64} {
		for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33, 255, 1024} {
			for _, as := range []int{0, 1, 15, 16, 17, 32} {
				key, nonce, p, a := random(32), random(ns), random(size), random(as)
				block, _ := aes.NewCipher(key)
				standard, err := cipher.NewGCMWithNonceSize(block, ns)
				if err != nil {
					t.Fatal(err)
				}
				want := standard.Seal(nil, nonce, p, a)
				ct, tag, err := AES256GCMEncrypt(key, nonce, p, a)
				if err != nil || !bytes.Equal(ct, want[:size]) || !bytes.Equal(tag, want[size:]) {
					t.Fatalf("mismatch nonce=%d size=%d aad=%d", ns, size, as)
				}
				got, err := AES256GCMDecrypt(key, nonce, ct, a, tag)
				if err != nil || !bytes.Equal(got, p) {
					t.Fatal("decryption mismatch")
				}
				tag[0] ^= 1
				if got, err := AES256GCMDecrypt(key, nonce, ct, a, tag); got != nil || !errors.Is(err, ErrAuthentication) {
					t.Fatal("accepted modified tag")
				}
			}
		}
	}
}

func TestGCMTrace(t *testing.T) {
	key, nonce, p := make([]byte, 32), make([]byte, 12), make([]byte, 16)
	var out bytes.Buffer
	if err := WriteGCMTrace(&out, key, nonce, p, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"K[14]", "Round 14 AddRoundKey", "SubBytes", "ShiftRows", "MixColumns",
		"cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("trace missing %q", want)
		}
	}
	for _, size := range []int{0, 1, 17} {
		out.Reset()
		p := make([]byte, size)
		ct, tag, _ := AES256GCMEncrypt(key, nonce, p, nil)
		if err := WriteGCMTrace(&out, key, nonce, p, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), fmt.Sprintf("Tag = GHASH XOR AES(K, J0) = %x", tag)) {
			t.Fatal("trace tag mismatch")
		}
		if size > 0 && !strings.Contains(out.String(), fmt.Sprintf("Ciphertext = plaintext XOR keystream = %x", ct[:min(16, size)])) {
			t.Fatal("trace ciphertext mismatch")
		}
	}
	if err := WriteGCMTrace(&out, nil, nonce, p, nil); err == nil {
		t.Fatal("accepted invalid key")
	}
	if err := WriteGCMTrace(failingWriter{}, key, nonce, p, nil); !errors.Is(err, errWrite) {
		t.Fatalf("writer error = %v", err)
	}
}

var errWrite = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestGCMParallelCompatibility(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(original)
	for _, workers := range []int{1, 2, 4} {
		runtime.GOMAXPROCS(workers)
		for _, size := range []int{32767, 32768, 32769, 65543, 262147} {
			t.Run(fmt.Sprintf("cpus%d/bytes%d", workers, size), func(t *testing.T) {
				key := bytes.Repeat([]byte{0x42}, 32)
				nonce := bytes.Repeat([]byte{0x19}, 12)
				p := bytes.Repeat([]byte{0xab}, size)
				aad := []byte("parallel message metadata")
				block, _ := aes.NewCipher(key)
				standard, _ := cipher.NewGCM(block)
				want := standard.Seal(nil, nonce, p, aad)
				ct, tag, err := AES256GCMEncrypt(key, nonce, p, aad)
				if err != nil || !bytes.Equal(ct, want[:size]) || !bytes.Equal(tag, want[size:]) {
					t.Fatal("parallel encryption differs from standard GCM")
				}
				got, err := AES256GCMDecrypt(key, nonce, ct, aad, tag)
				if err != nil || !bytes.Equal(got, p) {
					t.Fatal("parallel decryption failed")
				}
				ct[len(ct)-1] ^= 1
				if got, err := AES256GCMDecrypt(key, nonce, ct, aad, tag); got != nil || !errors.Is(err, ErrAuthentication) {
					t.Fatal("accepted modified ciphertext")
				}
			})
		}
	}
}

func TestParallelCounterWrap(t *testing.T) {
	original := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(original)
	key := make([]byte, 32)
	rk := expandKey(key)
	rkCopy := bytes.Clone(rk)
	var counter [16]byte
	copy(counter[:12], []byte("nonce prefix"))
	binary.BigEndian.PutUint32(counter[12:], 0xfffffbfe)
	input := bytes.Repeat([]byte{0x5a}, 65543)
	inputCopy := bytes.Clone(input)
	got := gcmCounterCrypt(rk, counter, input)
	want := make([]byte, len(input))
	block, _ := aes.NewCipher(key)
	var stream [16]byte
	for offset := 0; offset < len(input); offset += 16 {
		binary.BigEndian.PutUint32(counter[12:], binary.BigEndian.Uint32(counter[12:])+1)
		block.Encrypt(stream[:], counter[:])
		for i := 0; i < min(16, len(input)-offset); i++ {
			want[offset+i] = input[offset+i] ^ stream[i]
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatal("parallel inc32 wrap differs from AES reference")
	}
	if !bytes.Equal(rk, rkCopy) || !bytes.Equal(input, inputCopy) {
		t.Fatal("parallel operation modified shared inputs")
	}
}
