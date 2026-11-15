package main

import (
	"aes/enc"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type encryptedMessage struct {
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce_hex,omitempty"`
	IV         string `json:"iv_hex,omitempty"`
	Ciphertext string `json:"ciphertext_hex"`
	Tag        string `json:"tag_hex,omitempty"`
	AAD        string `json:"aad_hex,omitempty"`
}

func (r *encryptedMessage) save(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeNewFile(path, append(data, '\n'))
}

type terminalUI struct {
	in       *bufio.Reader
	out      io.Writer
	clear    bool
	mode     string
	key      []byte
	smallKey uint16
	aad      []byte
	last     *encryptedMessage
}

func runTUI(in io.Reader, out io.Writer, key, aad []byte) error {
	if len(key) != 32 {
		return errors.New("TUI requires a 32-byte key")
	}
	u := &terminalUI{in: bufio.NewReader(in), out: out, mode: "GCM", key: bytes.Clone(key), smallKey: 0x4af5, aad: bytes.Clone(aad)}
	if out == os.Stdout {
		info, err := os.Stdout.Stat()
		u.clear = err == nil && info.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
	}
	return u.run()
}

func (u *terminalUI) print(format string, args ...any) { fmt.Fprintf(u.out, format, args...) }

func (u *terminalUI) ask(label string) (string, error) {
	u.print("\n  %s", label)
	line, err := u.in.ReadString('\n')
	if err != nil && !(err == io.EOF && len(line) > 0) {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func (u *terminalUI) header() {
	if u.clear {
		u.print("\x1b[2J\x1b[H")
	}
	u.print("\n  Mode: %s\n", u.mode)
}

func (u *terminalUI) run() error {
	for {
		u.header()
		if u.mode == "S-AES" {
			u.print("\n  1  Encrypt a 16-bit block + verify round trip\n  2  Decrypt a 16-bit block (hex, or reuse last result)\n")
		} else {
			u.print("\n  1  Encrypt text + verify round trip\n  2  Decrypt text (hex input, or reuse last result)\n  3  Encrypt a file + restore it\n")
		}
		u.print("\n  7  Switch mode (GCM / ECB / S-AES / CBC)\n  8  Set key / generate a fresh key\n")
		if u.mode != "S-AES" {
			u.print("  9  Set additional authenticated data (GCM)\n")
		}
		u.print("  0  Exit\n")
		choice, err := u.ask("Select a number, then Enter > ")
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		choice = strings.ToLower(strings.TrimSpace(choice))
		if choice == "0" || choice == "q" {
			u.print("\n  Goodbye.\n")
			return nil
		}
		u.header()
		switch choice {
		case "1":
			err = u.encryptText()
		case "2":
			err = u.decryptText()
		case "3":
			err = u.fileRoundTrip()
		case "7":
			switch u.mode {
			case "GCM":
				u.mode = "ECB"
			case "ECB":
				u.mode = "S-AES"
			case "S-AES":
				u.mode = "CBC"
			default:
				u.mode = "GCM"
			}
			u.print("\n  Active mode: %s\n", u.mode)
			if u.mode == "S-AES" {
				u.print("  S-AES key: %04X (menu 8 changes it; AES-256 key is kept separately).\n", u.smallKey)
			}
		case "8":
			err = u.setKey()
		case "9":
			if u.mode == "S-AES" {
				err = errors.New("S-AES operates on one 16-bit block and does not use AAD")
				break
			}
			var value string
			value, err = u.ask("AAD (text; empty clears it): ")
			if err == nil {
				u.aad = []byte(value)
				u.print("\n  AAD updated (used only by GCM).\n")
			}
		default:
			u.print("\n  Choose one of the menu numbers.\n")
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			u.print("\n  ERROR: %s\n", err)
		}
		if _, err := u.ask("Press Enter to return to the menu..."); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (u *terminalUI) encrypt(message []byte) (*encryptedMessage, time.Duration, error) {
	if u.mode == "S-AES" {
		if len(message) != 2 {
			return nil, 0, errors.New("S-AES requires exactly one 16-bit block")
		}
		start := time.Now()
		ct := enc.SAESEncrypt(u.smallKey, binary.BigEndian.Uint16(message))
		elapsed := time.Since(start)
		return &encryptedMessage{Algorithm: "S-AES", Ciphertext: fmt.Sprintf("%04x", ct)}, elapsed, nil
	}
	r := &encryptedMessage{Algorithm: "AES-256-" + u.mode}
	var nonce, iv []byte
	if u.mode == "GCM" {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, 0, err
		}
	}
	if u.mode == "CBC" {
		iv = make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			return nil, 0, err
		}
	}
	start := time.Now()
	var ct, tag []byte
	var err error
	switch u.mode {
	case "GCM":
		ct, tag, err = enc.AES256GCMEncrypt(u.key, nonce, message, u.aad)
	case "CBC":
		ct, err = enc.AES256CBCEncrypt(u.key, iv, message)
	case "ECB":
		ct, err = enc.AES256ECBEncrypt(u.key, message)
	default:
		return nil, 0, errors.New("unsupported mode")
	}
	elapsed := time.Since(start)
	if err != nil {
		return nil, 0, err
	}
	r.Ciphertext = hex.EncodeToString(ct)
	if u.mode == "CBC" {
		r.IV = hex.EncodeToString(iv)
	}
	if u.mode == "GCM" {
		r.Nonce = hex.EncodeToString(nonce)
		r.Tag = hex.EncodeToString(tag)
		r.AAD = hex.EncodeToString(u.aad)
	}
	return r, elapsed, nil
}

func (u *terminalUI) decrypt(r *encryptedMessage) ([]byte, time.Duration, error) {
	decode := func(label, value string) ([]byte, error) {
		b, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("%s must be hexadecimal: %w", label, err)
		}
		return b, nil
	}
	ct, err := decode("ciphertext", r.Ciphertext)
	if err != nil {
		return nil, 0, err
	}
	if r.Algorithm == "S-AES" {
		if len(ct) != 2 {
			return nil, 0, errors.New("S-AES ciphertext must be exactly 4 hexadecimal characters")
		}
		start := time.Now()
		p := enc.SAESDecrypt(u.smallKey, binary.BigEndian.Uint16(ct))
		elapsed := time.Since(start)
		return []byte{byte(p >> 8), byte(p)}, elapsed, nil
	}
	var nonce, tag, aad, iv []byte
	if r.Algorithm == "AES-256-GCM" {
		if nonce, err = decode("nonce", r.Nonce); err != nil {
			return nil, 0, err
		}
		if tag, err = decode("tag", r.Tag); err != nil {
			return nil, 0, err
		}
		if aad, err = decode("AAD", r.AAD); err != nil {
			return nil, 0, err
		}
	} else if r.Algorithm == "AES-256-CBC" {
		if iv, err = decode("IV", r.IV); err != nil {
			return nil, 0, err
		}
	} else if r.Algorithm != "AES-256-ECB" {
		return nil, 0, errors.New("unsupported algorithm")
	}
	start := time.Now()
	var p []byte
	if r.Algorithm == "AES-256-GCM" {
		p, err = enc.AES256GCMDecrypt(u.key, nonce, ct, aad, tag)
	} else if r.Algorithm == "AES-256-CBC" {
		p, err = enc.AES256CBCDecrypt(u.key, iv, ct)
	} else {
		p, err = enc.AES256ECBDecrypt(u.key, ct)
	}
	return p, time.Since(start), err
}

func (u *terminalUI) summary(r *encryptedMessage, size int, encryptTime, decryptTime time.Duration, preview bool) {
	u.print("\n  Algorithm       %s\n  Input bytes     %d\n", r.Algorithm, size)
	if r.Algorithm == "S-AES" {
		u.print("  Demo key (hex)  %04X\n", u.smallKey)
	} else {
		u.print("  Demo key (hex)  %x\n", u.key)
	}
	ct := r.Ciphertext
	if preview && len(ct) > 128 {
		ct = ct[:128] + "... (first 64 bytes)"
	}
	u.print("  Ciphertext      %s\n", ct)
	if r.Algorithm == "AES-256-CBC" {
		u.print("  IV              %s\n", r.IV)
	}
	if r.Algorithm == "AES-256-GCM" {
		u.print("  Nonce           %s\n  Tag             %s\n  AAD (hex)       %s\n  Authentication  PASS\n", r.Nonce, r.Tag, r.AAD)
	} else if r.Algorithm == "S-AES" {
		u.print("  Padding         None (one 16-bit block)\n  Authentication  Not provided by S-AES\n")
	} else {
		u.print("  Padding         PKCS#7\n  Authentication  Not provided by %s\n", u.mode)
	}
	u.print("  Round trip      PASS (byte-for-byte match)\n  Encryption      %s\n  Decryption      %s\n", displayDuration(encryptTime), displayDuration(decryptTime))
}

func (u *terminalUI) roundTrip(message []byte) (*encryptedMessage, []byte, time.Duration, time.Duration, error) {
	r, et, err := u.encrypt(message)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	p, dt, err := u.decrypt(r)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	if !bytes.Equal(message, p) {
		return nil, nil, 0, 0, errors.New("round-trip verification failed")
	}
	u.last = r
	return r, p, et, dt, nil
}

func (u *terminalUI) encryptText() error {
	label := "Plaintext: "
	if u.mode == "S-AES" {
		label = "Plaintext block (4 hex characters; Enter uses D728): "
	}
	text, err := u.ask(label)
	if err != nil {
		return err
	}
	message := []byte(text)
	if u.mode == "S-AES" {
		if strings.TrimSpace(text) == "" {
			text = "D728"
		}
		block, err := parseSmallBlock(text)
		if err != nil {
			return err
		}
		message = []byte{byte(block >> 8), byte(block)}
	}
	r, p, et, dt, err := u.roundTrip(message)
	if err != nil {
		return err
	}
	u.summary(r, len(p), et, dt, false)
	if u.mode == "S-AES" {
		u.print("\n  Plaintext hex   %X\n  Decrypted hex   %X\n", message, p)
	} else {
		u.print("\n  Plaintext       %q\n  Decrypted       %q\n", text, p)
	}
	return u.inspect(r, p)
}

func (u *terminalUI) decryptText() error {
	r := &encryptedMessage{Algorithm: "AES-256-" + u.mode, AAD: hex.EncodeToString(u.aad)}
	if u.mode == "S-AES" {
		r.Algorithm, r.AAD = "S-AES", ""
	}
	ct, err := u.ask("Ciphertext hex (Enter reuses last result in this mode): ")
	if err != nil {
		return err
	}
	if strings.TrimSpace(ct) == "" && u.last != nil && u.last.Algorithm == r.Algorithm {
		r = u.last
	} else {
		r.Ciphertext = strings.TrimSpace(ct)
		if u.mode == "GCM" {
			if r.Nonce, err = u.ask("Nonce hex: "); err != nil {
				return err
			}
			if r.Tag, err = u.ask("Tag hex: "); err != nil {
				return err
			}
			r.Nonce, r.Tag = strings.TrimSpace(r.Nonce), strings.TrimSpace(r.Tag)
		}
		if u.mode == "CBC" {
			if r.IV, err = u.ask("IV hex (32 characters / 16 bytes): "); err != nil {
				return err
			}
			r.IV = strings.TrimSpace(r.IV)
		}
	}
	p, elapsed, err := u.decrypt(r)
	if err != nil {
		return err
	}
	if u.mode == "S-AES" {
		u.print("\n  Decrypted hex   %X\n  Decryption      %s\n", p, displayDuration(elapsed))
	} else {
		u.print("\n  Decrypted       %q\n  Plaintext hex   %x\n  Decryption      %s\n", p, p, displayDuration(elapsed))
	}
	if u.mode == "GCM" {
		u.print("  Authentication  PASS\n")
	} else if u.mode == "S-AES" {
		u.print("  Authentication  Not provided by S-AES\n")
	} else {
		u.print("  Padding         Valid (%s does not authenticate)\n", u.mode)
	}
	return u.inspect(r, p)
}

func (u *terminalUI) fileRoundTrip() error {
	if u.mode == "S-AES" {
		return errors.New("S-AES demonstrates one 16-bit block; switch to GCM, ECB or CBC for files")
	}
	path, err := u.ask("Input file path (text, image, or binary): ")
	if err != nil {
		return err
	}
	path = strings.Trim(strings.TrimSpace(path), "\"")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, err := u.ask("Restored file path (Enter uses input + .restored): ")
	if err != nil {
		return err
	}
	out = strings.Trim(strings.TrimSpace(out), "\"")
	if out == "" {
		out = path + ".restored"
	}
	r, p, et, dt, err := u.roundTrip(data)
	if err != nil {
		return err
	}
	if err := writeNewFile(out, p); err != nil {
		return err
	}
	u.summary(r, len(data), et, dt, true)
	u.print("\n  Original SHA256 %x\n  Restored SHA256 %x\n  Restored file   %s\n", sha256.Sum256(data), sha256.Sum256(p), out)
	return u.inspect(r, p)
}

// Inspection uses the actual message parameters after successful decryption.
func (u *terminalUI) inspect(r *encryptedMessage, plaintext []byte) error {
	if r.Algorithm == "S-AES" {
		return enc.WriteSAESTrace(u.out, u.smallKey, binary.BigEndian.Uint16(plaintext))
	}
	if r.Algorithm == "AES-256-ECB" {
		return enc.WriteECBTrace(u.out, u.key, plaintext)
	}
	if r.Algorithm == "AES-256-CBC" {
		iv, err := hex.DecodeString(r.IV)
		if err != nil {
			return err
		}
		return enc.WriteCBCTrace(u.out, u.key, iv, plaintext)
	}
	nonce, err := hex.DecodeString(r.Nonce)
	if err != nil {
		return err
	}
	aad, err := hex.DecodeString(r.AAD)
	if err != nil {
		return err
	}
	return enc.WriteGCMTrace(u.out, u.key, nonce, plaintext, aad)
}

func (u *terminalUI) setKey() error {
	if u.mode == "S-AES" {
		value, err := u.ask("S-AES key (4 hex characters; Enter generates a fresh 16-bit key): ")
		if err != nil {
			return err
		}
		var key uint16
		if strings.TrimSpace(value) == "" {
			var random [2]byte
			if _, err := rand.Read(random[:]); err != nil {
				return err
			}
			key = binary.BigEndian.Uint16(random[:])
		} else {
			key, err = parseSmallBlock(value)
			if err != nil {
				return err
			}
		}
		u.smallKey, u.last = key, nil
		u.print("\n  S-AES key updated. Previous result cleared.\n  Demo key (hex): %04X\n", key)
		return nil
	}
	value, err := u.ask("Key (64 hex characters; Enter generates a fresh key): ")
	if err != nil {
		return err
	}
	key, err := parseOrGenerateKey(value)
	if err != nil {
		return err
	}
	u.key, u.last = key, nil
	u.print("\n  Key updated. Previous result cleared.\n  Demo key (hex): %x\n", key)
	return nil
}

func parseSmallBlock(value string) (uint16, error) {
	value = strings.TrimSpace(value)
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 2 {
		return 0, errors.New("S-AES input must be exactly 4 hexadecimal characters (16 bits)")
	}
	return binary.BigEndian.Uint16(decoded), nil
}
