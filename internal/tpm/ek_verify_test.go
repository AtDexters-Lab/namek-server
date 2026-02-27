package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"log/slog"
	"math/big"
	"os"
	"testing"

	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
)

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// buildSyntheticAKPublic constructs a valid TPM2B_PUBLIC for an RSA signing key.
func buildSyntheticAKPublic(t *testing.T, pubKey *rsa.PublicKey) []byte {
	t.Helper()
	pub := tpm2legacy.Public{
		Type:       tpm2legacy.AlgRSA,
		NameAlg:    tpm2legacy.AlgSHA256,
		Attributes: tpm2legacy.FlagSignerDefault,
		RSAParameters: &tpm2legacy.RSAParams{
			Sign: &tpm2legacy.SigScheme{
				Alg:  tpm2legacy.AlgRSASSA,
				Hash: tpm2legacy.AlgSHA256,
			},
			KeyBits:    uint16(pubKey.N.BitLen()),
			ModulusRaw: pubKey.N.Bytes(),
		},
	}
	encoded, err := pub.Encode()
	if err != nil {
		t.Fatalf("encode synthetic AK public: %v", err)
	}
	return encoded
}

func TestParseAKPublic(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	akParams := buildSyntheticAKPublic(t, &key.PublicKey)

	v := &realVerifier{logger: noopLogger()}

	akPubKeyDER, akName, err := v.ParseAKPublic(akParams)
	if err != nil {
		t.Fatalf("ParseAKPublic: %v", err)
	}

	// Returned DER should match input
	if !bytes.Equal(akPubKeyDER, akParams) {
		t.Error("returned akPubKeyDER does not match input akParams")
	}

	// Name should be non-empty
	if len(akName) == 0 {
		t.Error("returned akName is empty")
	}

	// Name should round-trip through DecodeName
	name, err := tpm2legacy.DecodeName(bytes.NewBuffer(akName))
	if err != nil {
		t.Fatalf("DecodeName round-trip: %v", err)
	}
	if name.Digest == nil {
		t.Fatal("decoded name has no digest")
	}

	// Name should match the public key
	pub, err := tpm2legacy.DecodePublic(akParams)
	if err != nil {
		t.Fatalf("DecodePublic: %v", err)
	}
	matches, err := name.MatchesPublic(pub)
	if err != nil {
		t.Fatalf("MatchesPublic: %v", err)
	}
	if !matches {
		t.Error("decoded name does not match public key")
	}
}

func TestParseAKPublic_InvalidInput(t *testing.T) {
	v := &realVerifier{logger: noopLogger()}

	tests := []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"garbage", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"truncated", []byte{0x00, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := v.ParseAKPublic(tt.input)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestParseAKPublic_OversizedInput(t *testing.T) {
	v := &realVerifier{logger: noopLogger()}

	oversized := make([]byte, maxAKParamsSize+1)
	oversized[0] = 0x01
	_, _, err := v.ParseAKPublic(oversized)
	if err == nil {
		t.Error("expected error for oversized AK params")
	}
}

func TestMakeCredential(t *testing.T) {
	// Generate a real RSA-2048 EK keypair
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate EK key: %v", err)
	}

	// Build a synthetic AK public and parse it to get the name
	akKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate AK key: %v", err)
	}
	akParams := buildSyntheticAKPublic(t, &akKey.PublicKey)

	v := &realVerifier{logger: noopLogger()}

	_, akName, err := v.ParseAKPublic(akParams)
	if err != nil {
		t.Fatalf("ParseAKPublic: %v", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}

	out, err := v.MakeCredential(&ekKey.PublicKey, akName, secret)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	// Verify wire format: 2-byte length prefix + credBlob + encSecret
	if len(out) < 4 {
		t.Fatalf("output too short: %d bytes", len(out))
	}

	credBlobLen := int(binary.BigEndian.Uint16(out[0:2]))
	if credBlobLen <= 0 {
		t.Error("credBlob length is zero or negative")
	}
	if 2+credBlobLen > len(out) {
		t.Fatalf("credBlob length %d exceeds output size %d", credBlobLen, len(out))
	}

	encSecretLen := len(out) - 2 - credBlobLen
	if encSecretLen <= 0 {
		t.Error("encSecret portion is empty")
	}
}

func TestMakeCredential_InvalidName(t *testing.T) {
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate EK key: %v", err)
	}

	v := &realVerifier{logger: noopLogger()}

	// Empty name should fail at DecodeName
	_, err = v.MakeCredential(&ekKey.PublicKey, []byte{}, []byte("secret"))
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestVerifyQuote_InvalidFormat(t *testing.T) {
	// Build a valid AK public for the parse step
	akKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate AK key: %v", err)
	}
	akParams := buildSyntheticAKPublic(t, &akKey.PublicKey)

	v := &realVerifier{logger: noopLogger()}

	tests := []struct {
		name     string
		quoteB64 string
	}{
		{"not-base64", "!!!not-base64!!!"},
		{"too-short", base64.StdEncoding.EncodeToString([]byte{0x00, 0x01})},
		{"truncated-quote-length", func() string {
			// Quote length field says 100 bytes but only 10 available
			data := make([]byte, 14)
			binary.BigEndian.PutUint32(data[0:4], 100)
			return base64.StdEncoding.EncodeToString(data)
		}()},
		{"empty-signature", func() string {
			// Quote length = total - 4, leaving 0 bytes for signature
			data := make([]byte, 14)
			binary.BigEndian.PutUint32(data[0:4], 10)
			return base64.StdEncoding.EncodeToString(data)
		}()},
		{"oversized-payload", func() string {
			data := make([]byte, maxQuoteSize+100)
			binary.BigEndian.PutUint32(data[0:4], 10)
			return base64.StdEncoding.EncodeToString(data)
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.VerifyQuote(akParams, "test-nonce", tt.quoteB64)
			if err == nil {
				t.Error("expected error for invalid quote format")
			}
		})
	}
}

func TestVerifyQuote_InvalidAKPublic(t *testing.T) {
	v := &realVerifier{logger: noopLogger()}
	err := v.VerifyQuote([]byte{0xDE, 0xAD}, "nonce", base64.StdEncoding.EncodeToString([]byte("data")))
	if err == nil {
		t.Error("expected error for invalid AK public")
	}
}

func TestParseAKPublic_DifferentKeySizes(t *testing.T) {
	v := &realVerifier{logger: noopLogger()}

	// Test with a manually constructed 2048-bit modulus (non-zero)
	modulus := make([]byte, 256)
	modulus[0] = 0x01 // ensure non-zero big.Int
	pub := tpm2legacy.Public{
		Type:       tpm2legacy.AlgRSA,
		NameAlg:    tpm2legacy.AlgSHA256,
		Attributes: tpm2legacy.FlagSignerDefault,
		RSAParameters: &tpm2legacy.RSAParams{
			Sign: &tpm2legacy.SigScheme{
				Alg:  tpm2legacy.AlgRSASSA,
				Hash: tpm2legacy.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: new(big.Int).SetBytes(modulus).Bytes(),
		},
	}
	encoded, err := pub.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	_, name, err := v.ParseAKPublic(encoded)
	if err != nil {
		t.Fatalf("ParseAKPublic: %v", err)
	}
	if len(name) == 0 {
		t.Error("name is empty")
	}
}
