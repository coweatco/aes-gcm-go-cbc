package enc

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

func TestECBKnownAnswer(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	key := decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	p := decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	want := decode("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7")
	ct, err := AES256ECBEncrypt(key, p)
	if err != nil || len(ct) != 80 || !bytes.Equal(ct[:64], want) {
		t.Fatalf("ECB encryption = %x, %v", ct, err)
	}
	for offset := 0; offset < len(want); offset += 16 {
		got := aes256DecryptBlock(expandKey(key), want[offset:offset+16])
		if !bytes.Equal(got, p[offset:offset+16]) {
			t.Fatalf("known-answer decrypt block %d = %x", offset/16, got)
		}
	}
	got, err := AES256ECBDecrypt(key, ct)
	if err != nil || !bytes.Equal(got, p) {
		t.Fatalf("ECB decrypt = %x, %v", got, err)
	}
}

func TestECBCompatibility(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(original)
	rng := rand.New(rand.NewSource(256))
	for _, cpus := range []int{1, 2, 4} {
		runtime.GOMAXPROCS(cpus)
		for _, size := range []int{0, 1, 2, 14, 15, 16, 17, 31, 32, 33, 255, 32751, 32752, 32753, 65543} {
			key, p := make([]byte, 32), make([]byte, size)
			rng.Read(key)
			rng.Read(p)
			keyCopy, pCopy := bytes.Clone(key), bytes.Clone(p)
			padding := 16 - size%16
			padded := append(bytes.Clone(p), bytes.Repeat([]byte{byte(padding)}, padding)...)
			block, _ := aes.NewCipher(key)
			want := make([]byte, len(padded))
			for offset := 0; offset < len(padded); offset += 16 {
				block.Encrypt(want[offset:offset+16], padded[offset:offset+16])
			}
			ct, err := AES256ECBEncrypt(key, p)
			if err != nil || !bytes.Equal(ct, want) {
				t.Fatalf("encryption mismatch cpus=%d size=%d", cpus, size)
			}
			ctCopy := bytes.Clone(ct)
			got, err := AES256ECBDecrypt(key, ct)
			if err != nil || !bytes.Equal(got, p) {
				t.Fatalf("decryption mismatch cpus=%d size=%d", cpus, size)
			}
			if !bytes.Equal(key, keyCopy) || !bytes.Equal(p, pCopy) || !bytes.Equal(ct, ctCopy) {
				t.Fatal("input modified")
			}
		}
	}
}

func TestECBInvalidInputs(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if ct, err := AES256ECBEncrypt(make([]byte, size), nil); ct != nil || err == nil {
			t.Fatal("accepted invalid encryption key")
		}
		if p, err := AES256ECBDecrypt(make([]byte, size), make([]byte, 16)); p != nil || err == nil {
			t.Fatal("accepted invalid decryption key")
		}
	}
	key := make([]byte, 32)
	for _, size := range []int{0, 1, 15, 17, 31} {
		if p, err := AES256ECBDecrypt(key, make([]byte, size)); p != nil || err == nil {
			t.Fatal("accepted invalid ciphertext length")
		}
	}
	block, _ := aes.NewCipher(key)
	for _, pad := range []byte{0, 17, 255} {
		invalid := bytes.Repeat([]byte{pad}, 16)
		ct := make([]byte, 16)
		block.Encrypt(ct, invalid)
		if p, err := AES256ECBDecrypt(key, ct); p != nil || !errors.Is(err, ErrInvalidPadding) {
			t.Fatal("accepted invalid padding length")
		}
	}
	for padding := 2; padding <= 16; padding++ {
		for pos := 16 - padding; pos < 15; pos++ {
			invalid := bytes.Repeat([]byte{byte(padding)}, 16)
			invalid[pos] ^= 1
			ct := make([]byte, 16)
			block.Encrypt(ct, invalid)
			if p, err := AES256ECBDecrypt(key, ct); p != nil || !errors.Is(err, ErrInvalidPadding) {
				t.Fatal("accepted inconsistent padding")
			}
		}
	}
}

func TestECBTrace(t *testing.T) {
	key := make([]byte, 32)
	for _, size := range []int{0, 1, 15, 16, 17, 32} {
		p := bytes.Repeat([]byte{0x42}, size)
		ct, err := AES256ECBEncrypt(key, p)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := WriteECBTrace(&out, key, p); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), fmt.Sprintf("First ciphertext block = %x", ct[:16])) {
			t.Fatalf("trace differs from encryption for size %d", size)
		}
		if !strings.Contains(out.String(), "Round 14 AddRoundKey") {
			t.Fatal("missing round states")
		}
	}
	if err := WriteECBTrace(failingWriter{}, key, nil); !errors.Is(err, errWrite) {
		t.Fatalf("write error = %v", err)
	}
	if err := WriteECBTrace(&bytes.Buffer{}, nil, nil); err == nil {
		t.Fatal("accepted invalid key")
	}
}
