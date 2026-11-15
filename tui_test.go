package main

import (
	"aes/enc"
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runUIScript(t *testing.T, steps ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runTUI(strings.NewReader(strings.Join(steps, "\n")+"\n"), &out, make([]byte, 32), nil); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestTUITextModes(t *testing.T) {
	for _, mode := range []string{"GCM", "ECB", "CBC"} {
		t.Run(mode, func(t *testing.T) {
			steps := []string{}
			if mode == "ECB" {
				steps = append(steps, "7", "")
			}
			if mode == "CBC" {
				steps = append(steps, "7", "", "7", "", "7", "")
			}
			steps = append(steps, "1", "Hello, 世界", "", "2", "", "", "0")
			out := runUIScript(t, steps...)
			for _, want := range []string{"AES-256-" + mode, "Round trip      PASS", `Decrypted       "Hello, 世界"`, "Goodbye.", "K[14]", "Round 14 AddRoundKey"} {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q", want)
				}
			}
			if strings.Contains(out, "ERROR:") {
				t.Fatal(out)
			}
			if strings.Contains(out, "4  Inspect") {
				t.Fatal("inspection must not be a menu option")
			}
			if strings.Count(out, "AES-256 round keys (hex):") != 2 {
				t.Fatal("encryption and decryption must both inspect automatically")
			}
		})
	}
}

func TestTUIRecoversFromInvalidKey(t *testing.T) {
	out := runUIScript(t, "8", "bad key", "", "1", "still works", "", "0")
	if !strings.Contains(out, "ERROR: key must be exactly 64") || !strings.Contains(out, "Round trip      PASS") {
		t.Fatal(out)
	}
}

func TestTUITamperedDecrypt(t *testing.T) {
	key, nonce := make([]byte, 32), make([]byte, 12)
	ct, tag, err := enc.AES256GCMEncrypt(key, nonce, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tag[0] ^= 1
	out := runUIScript(t, "2", hex.EncodeToString(ct), hex.EncodeToString(nonce), hex.EncodeToString(tag), "", "0")
	if !strings.Contains(out, "ERROR: aes256gcm: authentication failed") || strings.Contains(out, "Decrypted       ") {
		t.Fatal(out)
	}
}

func TestTUIFileRoundTrip(t *testing.T) {
	for _, mode := range []string{"GCM", "ECB", "CBC"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			input, restored := filepath.Join(dir, "source.bin"), filepath.Join(dir, "restored.bin")
			data := bytes.Repeat([]byte{0, 1, 255, 42}, 20000)
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			steps := []string{}
			if mode == "ECB" {
				steps = append(steps, "7", "")
			}
			if mode == "CBC" {
				steps = append(steps, "7", "", "7", "", "7", "")
			}
			steps = append(steps, "3", input, restored, "", "0")
			out := runUIScript(t, steps...)
			if strings.Contains(out, "ERROR:") {
				t.Fatal(out)
			}
			got, err := os.ReadFile(restored)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("file restore: %v", err)
			}
		})
	}
}

func TestTUIRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original.txt")
	if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	out := runUIScript(t, "3", path, path, "", "0")
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "keep me" || !strings.Contains(out, "ERROR:") {
		t.Fatalf("overwrite check failed: %v\n%s", err, out)
	}
}

func TestTUITraceAndSettings(t *testing.T) {
	key := strings.Repeat("01", 32)
	out := runUIScript(t, "8", key, "", "9", "metadata", "", "1", "trace me", "", "0")
	for _, want := range []string{"Key updated", "AAD updated", "K[14]", "Round 14 AddRoundKey", "AAD (hex)       6d65746164617461"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestTUIEOF(t *testing.T) {
	for _, script := range []string{"", "1\n", "7\n", "2\n00\n", "8\n"} {
		var out bytes.Buffer
		if err := runTUI(strings.NewReader(script), &out, make([]byte, 32), nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTUISmallMode(t *testing.T) {
	out := runUIScript(t,
		"7", "", "7", "", // GCM -> ECB -> S-AES.
		"1", "D728", "", "2", "", "", "2", "24EC", "",
		"7", "", "7", "", "1", "AES key preserved", "", "0",
	)
	for _, want := range []string{
		"Mode: S-AES", "S-AES key: 4AF5", "Ciphertext      24ec", "Decrypted hex   D728",
		"Key expansion", "RotNib(w1=F5)", "K2 = w4 || w5", "Inverse round 1 InvMixColumns",
		"Matches original: PASS", "Active mode: GCM", `Decrypted       "AES key preserved"`,
		"Demo key (hex)  " + strings.Repeat("00", 32),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "ERROR:") {
		t.Fatal(out)
	}
	if strings.Count(out, "S-AES: 16-bit block, 16-bit key, two rounds") != 3 {
		t.Fatal("all S-AES operations must inspect automatically")
	}
}

func TestTUISmallKeyAndValidation(t *testing.T) {
	out := runUIScript(t, "7", "", "7", "",
		"1", "too long", "", "8", "not hex", "",
		"8", "BEEF", "", "1", "", "", "2", "123456", "", "0")
	for _, want := range []string{
		"ERROR: S-AES input must be exactly 4 hexadecimal characters",
		"S-AES key updated", "Demo key (hex): BEEF", "Decrypted hex   D728",
		fmt.Sprintf("Ciphertext      %04x", enc.SAESEncrypt(0xbeef, 0xd728)),
		"ERROR: S-AES ciphertext must be exactly 4 hexadecimal characters",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestTUISmallMenu(t *testing.T) {
	var out bytes.Buffer
	u := &terminalUI{in: bufio.NewReader(strings.NewReader("0\n")), out: &out, mode: "S-AES"}
	if err := u.run(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Encrypt a file") || strings.Contains(out.String(), "Set additional") {
		t.Fatal("S-AES menu must show only supported operations")
	}
	if err := u.fileRoundTrip(); err == nil {
		t.Fatal("S-AES must reject file mode")
	}
}

func TestTUICBCManualDecrypt(t *testing.T) {
	key, iv := make([]byte, 32), bytes.Repeat([]byte{0x42}, 16)
	ct, err := enc.AES256CBCEncrypt(key, iv, []byte("CBC manual input"))
	if err != nil {
		t.Fatal(err)
	}
	out := runUIScript(t, "7", "", "7", "", "7", "", "2", hex.EncodeToString(ct), hex.EncodeToString(iv), "", "2", hex.EncodeToString(ct), "00", "", "0")
	for _, want := range []string{`Decrypted       "CBC manual input"`, "CBC intermediates", "IV hex (32 characters / 16 bytes)", "ERROR: aes256cbc: IV must contain exactly 16 bytes"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestTUICBCFreshIV(t *testing.T) {
	u := &terminalUI{mode: "CBC", key: make([]byte, 32)}
	first, _, err := u.encrypt([]byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := u.encrypt([]byte("same plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.IV) != 32 || first.IV == second.IV || first.Ciphertext == second.Ciphertext {
		t.Fatal("CBC must generate fresh IVs")
	}
}
