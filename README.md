# AES classroom demo

Run `go run .` or `go run . -tui` from the directory containing `go.mod` to open the terminal interface. Install a Go toolchain compatible with the version declared in `go.mod` (`1.27.1`). Keep `main.go` and `tui.go` in the project root and the algorithm files in `enc/`. If downloaded filenames include `(1)`, restore their original names, such as `go.mod`, `main.go`, and `tui_test.go`.

The interface starts in GCM with a generated 32-byte key. Menu 7 cycles through **GCM → ECB → S-AES → CBC → GCM**. Press Enter after each selection and again when prompted to return to the menu. Menu 8 sets the key for the current mode or generates a fresh key when left blank. AES-256 uses 64 hexadecimal characters. S-AES uses four and keeps its key separately. Menu 9 sets additional authenticated data (AAD) for GCM. Type `0` or `q` to exit.

Menu 1 encrypts text and verifies the round trip. Menu 2 decrypts hexadecimal ciphertext or reuses the latest result for the selected mode when the input is blank. Manual GCM decryption also requires the nonce and tag and uses the current AAD. Manual CBC decryption requires a 16-byte IV entered as 32 hexadecimal characters. Menu 3 encrypts a file and restores it in GCM, ECB, or CBC. Enter a new output path because file recovery refuses to overwrite existing files. A successful file round trip reports a byte-for-byte match and displays the original and restored SHA-256 hashes.

## Command-line GCM demo

Command-line flags run the AES-256-GCM demo directly:

```powershell
go run . -text "Hello AES" -aad "class demo" -trace
go run . -in example.txt -out restored.txt -save encrypted.json
go run . -in photo.png -out restored.png -save photo-encrypted.json
```

Place the input file in the project directory or supply its full path. The demo encrypts and immediately decrypts the input. It reports the byte count, ciphertext, authentication result, round-trip result, and encryption and decryption times. File output previews the first 64 bytes of ciphertext. The `-save` flag writes the complete ciphertext, nonce, tag, and AAD to JSON. Keep the demo key separately if needed. The CLI does not load saved bundles for standalone decryption.

The `-trace` flag prints the round keys, GCM intermediate values, and AES states for the first counter block. Short operations may be reported as `below timer resolution`.

## AES-256-ECB and AES-256-CBC

`enc/ebc.go` implements ECB and preserves the project's filename spelling. `enc/cbc.go` implements CBC. Both modes use PKCS#7 padding. CBC uses a 16-byte IV, which the terminal interface generates for encryption and displays with the result. ECB encrypts blocks independently. Both modes provide encryption without authentication. GCM verifies the authentication tag before returning plaintext.

## S-AES worked example

`enc/small.go` implements the two-round S-AES teaching cipher with a 16-bit block and key. In the terminal interface:

1. From GCM, select menu 7 twice to reach **S-AES**.
2. Select menu 8 and enter the key `A73B`.
3. Select menu 1 and enter the plaintext block `6F6B`.
4. Compare the trace with the hand calculation. The round keys are `A73B`, `1C27`, and `7651`. The expected ciphertext is `0738` and the recovered plaintext is `6F6B`.

The trace displays the intermediate transformations for the worked example.

## Validation

```powershell
go test -v -count=1 ./...
go test -v -count=1 ./enc -run '^TestSAES'
go vet ./...
```

The ECB and CBC known-answer tests use examples from [NIST SP 800-38A](https://doi.org/10.6028/NIST.SP.800-38A). Compatibility tests compare results against Go's standard cryptography library. The S-AES known-answer test uses plaintext `D728`, key `4AF5`, and expected ciphertext `24EC`. Use the menu procedure above to verify the separate hand-calculation example.

If the build reports `undefined: enc.AES256CBCEncrypt` or `undefined: enc.WriteCBCTrace`, check that `enc/cbc.go` is present and that the root and `enc/` files come from the same version. Run commands from the directory containing `go.mod`.

This implementation is for classroom use. The demo prints keys and intermediate states, so use sample data and demo keys.
