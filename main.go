package main

import (
	"aes/enc"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	text := flag.String("text", "Hello, AES-256-GCM!", "plaintext to encrypt")
	keyHex := flag.String("key", "", "32-byte key as 64 hex characters; blank generates a key")
	aadText := flag.String("aad", "", "additional authenticated data")
	input := flag.String("in", "", "read plaintext bytes from a text file or image")
	output := flag.String("out", "", "restored file destination (requires -in)")
	bundle := flag.String("save", "", "save nonce, ciphertext, tag and AAD as JSON hex fields")
	trace := flag.Bool("trace", false, "show round keys, AES states, counter, keystream and GHASH")
	tamper := flag.Bool("tamper", false, "demonstrate rejection of a modified tag")
	tui := flag.Bool("tui", false, "open the interactive terminal interface")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected arguments; use -help for usage")
	}
	if *output != "" && *input == "" {
		return errors.New("-out requires -in")
	}
	key, err := parseOrGenerateKey(*keyHex)
	if err != nil {
		return err
	}
	if *tui || len(os.Args) == 1 {
		return runTUI(os.Stdin, os.Stdout, key, []byte(*aadText))
	}
	message := []byte(*text)
	if *input != "" {
		var err error
		message, err = os.ReadFile(*input)
		if err != nil {
			return err
		}
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	aad := []byte(*aadText)
	start := time.Now()
	ct, tag, err := enc.AES256GCMEncrypt(key, nonce, message, aad)
	encryptTime := time.Since(start)
	if err != nil {
		return err
	}
	start = time.Now()
	plaintext, err := enc.AES256GCMDecrypt(key, nonce, ct, aad, tag)
	decryptTime := time.Since(start)
	if err != nil {
		return err
	}
	if !bytes.Equal(message, plaintext) {
		return errors.New("round-trip verification failed")
	}
	fmt.Printf("Algorithm: AES-256-GCM\nInput size: %d bytes\nKey (hex, demo only): %x\nNonce (hex): %x\nAAD: %q\n", len(message), key, nonce, aad)
	if *input == "" {
		fmt.Printf("Plaintext: %q\nCiphertext (hex): %x\nTag (hex): %x\nDecrypted: %q\n", message, ct, tag, plaintext)
	} else {
		fmt.Printf("Input file: %s\nCiphertext preview (first %d bytes, hex): %x\nTag (hex): %x\nOriginal SHA-256: %x\nRestored SHA-256: %x\n", *input, min(64, len(ct)), ct[:min(64, len(ct))], tag, sha256.Sum256(message), sha256.Sum256(plaintext))
		if *output == "" {
			*output = *input + ".decrypted"
		}
		if err := writeNewFile(*output, plaintext); err != nil {
			return err
		}
		fmt.Printf("Restored file: %s\n", *output)
	}
	fmt.Printf("Authentication: PASS\nRound trip: PASS (byte-for-byte match)\nEncryption time: %s\nDecryption time: %s\n", displayDuration(encryptTime), displayDuration(decryptTime))
	if *bundle != "" {
		r := encryptedMessage{
			Algorithm: "AES-256-GCM", Nonce: hex.EncodeToString(nonce),
			Ciphertext: hex.EncodeToString(ct), Tag: hex.EncodeToString(tag), AAD: hex.EncodeToString(aad),
		}
		if err := r.save(*bundle); err != nil {
			return err
		}
		fmt.Printf("Encrypted bundle: %s (key is not stored)\n", *bundle)
	}
	if *trace {
		if err := enc.WriteGCMTrace(os.Stdout, key, nonce, message, aad); err != nil {
			return err
		}
	}
	if *tamper {
		badTag := bytes.Clone(tag)
		badTag[0] ^= 1
		got, err := enc.AES256GCMDecrypt(key, nonce, ct, aad, badTag)
		if got != nil || !errors.Is(err, enc.ErrAuthentication) {
			return errors.New("tamper demonstration unexpectedly succeeded")
		}
		fmt.Println("Tamper demo: changed one tag bit; authentication failed and no plaintext was released.")
	}
	return nil
}

func displayDuration(d time.Duration) string {
	if d == 0 {
		return "below timer resolution"
	}
	return d.String()
}

func parseOrGenerateKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		return key, err
	}
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("key must be exactly 64 hexadecimal characters (32 bytes)")
	}
	return key, nil
}

func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}
