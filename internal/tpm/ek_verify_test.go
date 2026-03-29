package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
			_, err := v.VerifyQuote(akParams, []byte("test-nonce"), tt.quoteB64, nil)
			if err == nil {
				t.Error("expected error for invalid quote format")
			}
		})
	}
}

func TestVerifyQuote_InvalidAKPublic(t *testing.T) {
	v := &realVerifier{logger: noopLogger()}
	_, err := v.VerifyQuote([]byte{0xDE, 0xAD}, []byte("nonce"), base64.StdEncoding.EncodeToString([]byte("data")), nil)
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

// buildSelfSignedCertDER creates a minimal self-signed X.509 certificate in DER form.
func buildSelfSignedCertDER(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ek"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der, key
}

func TestTrimDERTrailingData(t *testing.T) {
	certDER, _ := buildSelfSignedCertDER(t)

	tests := []struct {
		name    string
		input   []byte
		want    []byte
		trimmed bool
	}{
		{"clean cert unchanged", certDER, certDER, false},
		{"trailing null byte", append(bytes.Clone(certDER), 0x00), certDER, true},
		{"trailing garbage bytes", append(bytes.Clone(certDER), 0xDE, 0xAD, 0xBE, 0xEF), certDER, true},
		{"trailing valid ASN.1 element", append(bytes.Clone(certDER), certDER...), certDER, true},
		{"invalid ASN.1 returns original", []byte{0xFF, 0xFF}, []byte{0xFF, 0xFF}, false},
		{"nil input", nil, nil, false},
		{"empty input", []byte{}, []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, didTrim := trimDERTrailingData(tt.input)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("trimDERTrailingData: got %d bytes, want %d bytes", len(got), len(tt.want))
			}
			if didTrim != tt.trimmed {
				t.Errorf("trimDERTrailingData trimmed=%v, want %v", didTrim, tt.trimmed)
			}
		})
	}
}

func TestParseEKCert_TrailingData(t *testing.T) {
	certDER, _ := buildSelfSignedCertDER(t)
	v := &realVerifier{logger: noopLogger()}

	// Clean cert parses fine
	cert, err := v.ParseEKCert(certDER)
	if err != nil {
		t.Fatalf("clean cert: %v", err)
	}
	if cert.Subject.CommonName != "test-ek" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}

	// Cert with trailing bytes also parses
	dirty := append(bytes.Clone(certDER), 0x00, 0x00, 0x00)
	cert2, err := v.ParseEKCert(dirty)
	if err != nil {
		t.Fatalf("trailing data cert: %v", err)
	}
	if cert2.Subject.CommonName != "test-ek" {
		t.Errorf("unexpected CN: %s", cert2.Subject.CommonName)
	}
}

func TestExtractEKPublicKey_TrailingData(t *testing.T) {
	certDER, key := buildSelfSignedCertDER(t)
	v := &realVerifier{logger: noopLogger()}

	dirty := append(bytes.Clone(certDER), 0x00, 0xFF)
	pubKey, err := v.ExtractEKPublicKey(dirty)
	if err != nil {
		t.Fatalf("ExtractEKPublicKey with trailing data: %v", err)
	}
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected RSA public key")
	}
	if rsaPub.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("extracted public key does not match")
	}
}

func TestEKFingerprint_Normalized(t *testing.T) {
	certDER, _ := buildSelfSignedCertDER(t)
	v := &realVerifier{logger: noopLogger()}

	clean := v.EKFingerprint(certDER)
	dirty := v.EKFingerprint(append(bytes.Clone(certDER), 0x00, 0x00))

	if clean != dirty {
		t.Errorf("fingerprints differ:\n  clean: %s\n  dirty: %s", clean, dirty)
	}

	// Sanity: fingerprint is 64 hex chars (SHA-256)
	if len(clean) != 64 {
		t.Errorf("unexpected fingerprint length: %d", len(clean))
	}
}
