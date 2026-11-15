package enc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

func TestCBCKnownAnswer(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// NIST SP 800-38A, F.2.5 AES-256-CBC. API adds one padding block.
	key := decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := decode("000102030405060708090a0b0c0d0e0f")
	p := decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	want := decode("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")
	ct, err := AES256CBCEncrypt(key, iv, p)
	if err != nil || len(ct) != 80 || !bytes.Equal(ct[:64], want) {
		t.Fatalf("CBC = %x, %v", ct, err)
	}
	got, err := AES256CBCDecrypt(key, iv, ct)
	if err != nil || !bytes.Equal(got, p) {
		t.Fatalf("decrypt = %x, %v", got, err)
	}
}

func TestCBCCompatibility(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(original)
	rng := rand.New(rand.NewSource(256))
	for _, cpus := range []int{1, 4} {
		runtime.GOMAXPROCS(cpus)
		for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33, 255, 32751, 32752, 32753, 65543, 262147} {
			key, iv, p := make([]byte, 32), make([]byte, 16), make([]byte, size)
			rng.Read(key)
			rng.Read(iv)
			rng.Read(p)
			keyCopy, ivCopy, pCopy := bytes.Clone(key), bytes.Clone(iv), bytes.Clone(p)
			padding := 16 - size%16
			padded := append(bytes.Clone(p), bytes.Repeat([]byte{byte(padding)}, padding)...)
			block, _ := aes.NewCipher(key)
			want := make([]byte, len(padded))
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(want, padded)
			ct, err := AES256CBCEncrypt(key, iv, p)
			if err != nil || !bytes.Equal(ct, want) {
				t.Fatalf("encryption mismatch size=%d cpus=%d", size, cpus)
			}
			ctCopy := bytes.Clone(ct)
			got, err := AES256CBCDecrypt(key, iv, want)
			if err != nil || !bytes.Equal(got, p) {
				t.Fatalf("decryption mismatch size=%d cpus=%d", size, cpus)
			}
			if !bytes.Equal(key, keyCopy) || !bytes.Equal(iv, ivCopy) || !bytes.Equal(p, pCopy) || !bytes.Equal(ct, ctCopy) || !bytes.Equal(want, ctCopy) {
				t.Fatal("input modified")
			}
		}
	}
}

func TestCBCInvalidInputs(t *testing.T) {
	key, iv := make([]byte, 32), make([]byte, 16)
	for _, size := range []int{0, 16, 24, 31, 33} {
		if ct, err := AES256CBCEncrypt(make([]byte, size), iv, nil); ct != nil || err == nil {
			t.Fatal("accepted invalid key")
		}
		if p, err := AES256CBCDecrypt(make([]byte, size), iv, make([]byte, 16)); p != nil || err == nil {
			t.Fatal("decrypt accepted invalid key")
		}
	}
	for _, size := range []int{0, 1, 15, 17, 32} {
		if ct, err := AES256CBCEncrypt(key, make([]byte, size), nil); ct != nil || err == nil {
			t.Fatal("accepted invalid IV")
		}
		if p, err := AES256CBCDecrypt(key, make([]byte, size), make([]byte, 16)); p != nil || err == nil {
			t.Fatal("decrypt accepted invalid IV")
		}
	}
	for _, size := range []int{0, 1, 15, 17, 31} {
		if p, err := AES256CBCDecrypt(key, iv, make([]byte, size)); p != nil || err == nil {
			t.Fatal("accepted invalid ciphertext length")
		}
	}
	block, _ := aes.NewCipher(key)
	invalid := [][]byte{make([]byte, 16), bytes.Repeat([]byte{17}, 16), bytes.Repeat([]byte{255}, 16)}
	for padding := 2; padding <= 16; padding++ {
		for pos := 16 - padding; pos < 15; pos++ {
			p := bytes.Repeat([]byte{byte(padding)}, 16)
			p[pos] ^= 1
			invalid = append(invalid, p)
		}
	}
	for _, p := range invalid {
		ct := make([]byte, len(p))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, p)
		if got, err := AES256CBCDecrypt(key, iv, ct); got != nil || !errors.Is(err, ErrInvalidPadding) {
			t.Fatal("accepted invalid padding")
		}
	}
}

func TestCBCTrace(t *testing.T) {
	key, iv := make([]byte, 32), bytes.Repeat([]byte{0x42}, 16)
	for _, size := range []int{0, 1, 15, 16, 17, 32, 257} {
		p := bytes.Repeat([]byte{0xab}, size)
		ct, err := AES256CBCEncrypt(key, iv, p)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := WriteCBCTrace(&out, key, iv, p); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < min(2, len(ct)/16); i++ {
			if !strings.Contains(out.String(), fmt.Sprintf("C[%d] = %x", i, ct[i*16:(i+1)*16])) {
				t.Fatalf("trace differs from encryption size=%d block=%d", size, i)
			}
		}
		for _, want := range []string{"K[14]", "Round 14 AddRoundKey", fmt.Sprintf("IV = %x", iv), "Recovered padded P[0]"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("missing %q", want)
			}
		}
		if strings.Contains(out.String(), "  Block 2\n") {
			t.Fatal("file trace must be bounded")
		}
	}
	if err := WriteCBCTrace(failingWriter{}, key, iv, nil); !errors.Is(err, errWrite) {
		t.Fatalf("write error = %v", err)
	}
	if err := WriteCBCTrace(&bytes.Buffer{}, key, nil, nil); err == nil {
		t.Fatal("accepted invalid IV")
	}
	if err := WriteCBCTrace(&bytes.Buffer{}, nil, iv, nil); err == nil {
		t.Fatal("accepted invalid key")
	}
}
