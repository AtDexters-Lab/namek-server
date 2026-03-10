package tpm

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/google/go-attestation/attest"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
)

type realVerifier struct {
	hardwareCAs *x509.CertPool
	softwareCAs *x509.CertPool
	logger      *slog.Logger
}

func NewVerifier(cfg config.TPMConfig, logger *slog.Logger) (Verifier, error) {
	v := &realVerifier{
		hardwareCAs: x509.NewCertPool(),
		softwareCAs: x509.NewCertPool(),
		logger:      logger,
	}

	loaded := 0
	if cfg.TrustedCACertsDir != "" {
		loaded += v.loadCertsFromDir(cfg.TrustedCACertsDir, v.hardwareCAs, "hardware")
	}
	if cfg.SoftwareCACertsDir != "" {
		loaded += v.loadCertsFromDir(cfg.SoftwareCACertsDir, v.softwareCAs, "software")
	}

	if loaded == 0 {
		return nil, fmt.Errorf("no TPM CA certificates loaded: configure tpm.trustedCACertsDir and/or tpm.softwareCACertsDir")
	}
	return v, nil
}

func (v *realVerifier) VerifyEKCert(ekCertDER []byte) (string, crypto.PublicKey, error) {
	cert, err := x509.ParseCertificate(ekCertDER)
	if err != nil {
		return "", nil, fmt.Errorf("parse EK cert: %w", err)
	}

	// TPM EK certs contain SAN (2.5.29.17) with DirectoryName entries for TPM
	// manufacturer info. Go's x509 can't parse these custom name types and marks
	// SAN as an unhandled critical extension. We clear this since we don't need
	// to validate TPM-specific SAN content for EK trust verification.
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}
	filtered := cert.UnhandledCriticalExtensions[:0]
	for _, oid := range cert.UnhandledCriticalExtensions {
		if !oid.Equal(oidSAN) {
			filtered = append(filtered, oid)
		}
	}
	cert.UnhandledCriticalExtensions = filtered

	// EK certs typically lack ExtKeyUsageServerAuth (or have TPM-specific OIDs),
	// so we use ExtKeyUsageAny to avoid rejecting valid certs.
	ekVerifyOpts := func(roots *x509.CertPool) x509.VerifyOptions {
		return x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
	}

	// Try hardware CA pool first
	if _, err := cert.Verify(ekVerifyOpts(v.hardwareCAs)); err == nil {
		return IdentityClassHardwareTPM, cert.PublicKey, nil
	}

	// Try software CA pool
	if _, err := cert.Verify(ekVerifyOpts(v.softwareCAs)); err == nil {
		return IdentityClassSoftwareTPM, cert.PublicKey, nil
	}

	return "", nil, fmt.Errorf("EK cert not trusted by any CA pool")
}

const (
	// maxQuoteSize caps decoded quote payload to prevent DoS via oversized data.
	maxQuoteSize = 4096
	// maxAKParamsSize caps TPM2B_PUBLIC input to a reasonable bound.
	maxAKParamsSize = 2048
	// symBlockSize is the AES block size (always 16 for AES-128/192/256) per
	// TCG EK Credential Profile 2.0, section 2.1.5.1.
	symBlockSize = 16
)

// VerifyQuote verifies a TPM2 quote signed by the AK.
//
// Wire format for quoteB64 (after base64 decode):
//
//	uint32(quoteLen) [big-endian] || TPMS_ATTEST || TPMT_SIGNATURE
//
// PCR validation is intentionally skipped (nil PCRs) at MVP — the quote serves
// as AK proof-of-possession only. PCR policy checking is a follow-up.
func (v *realVerifier) VerifyQuote(akPubKeyDER []byte, nonce string, quoteB64 string) error {
	akPub, err := attest.ParseAKPublic(akPubKeyDER)
	if err != nil {
		return fmt.Errorf("parse AK public: %w", err)
	}

	// Pre-check base64 string length to avoid allocating oversized buffers.
	// Base64 encodes 3 bytes as 4 chars, so decoded size ≈ len*3/4.
	if len(quoteB64) > maxQuoteSize*2 {
		return fmt.Errorf("quote base64 string too large: %d chars", len(quoteB64))
	}

	data, err := base64.StdEncoding.DecodeString(quoteB64)
	if err != nil {
		return fmt.Errorf("decode quote base64: %w", err)
	}
	if len(data) > maxQuoteSize {
		return fmt.Errorf("quote data exceeds max size (%d > %d)", len(data), maxQuoteSize)
	}
	if len(data) < 4 {
		return fmt.Errorf("quote data too short: %d bytes", len(data))
	}

	ql := int(binary.BigEndian.Uint32(data[0:4]))
	if ql+4 > len(data) {
		return fmt.Errorf("quote length exceeds available data: %d + 4 header > %d total", ql, len(data))
	}
	if len(data)-4-ql <= 0 {
		return fmt.Errorf("signature portion is empty (quote %d bytes, total %d bytes)", ql, len(data))
	}

	quoteBytes := data[4 : 4+ql]
	sigBytes := data[4+ql:]

	if err := akPub.Verify(attest.Quote{Quote: quoteBytes, Signature: sigBytes}, nil, []byte(nonce)); err != nil {
		v.logger.Warn("quote verification failed", "error", err)
		return fmt.Errorf("verify quote: %w", err)
	}

	v.logger.Debug("quote verification succeeded")
	return nil
}

// MakeCredential creates an encrypted credential blob using the EK public key.
//
// Wire format of returned bytes:
//
//	uint16(len(credBlob)) [big-endian] || credBlob (TPM2B_ID_OBJECT) || encSecret (TPM2B_ENCRYPTED_SECRET)
//
// The client reads the 2-byte length, splits credBlob and encSecret, then passes
// them separately to TPM2_ActivateCredential.
func (v *realVerifier) MakeCredential(ekPubKey crypto.PublicKey, akName []byte, secret []byte) ([]byte, error) {
	name, err := tpm2legacy.DecodeName(bytes.NewBuffer(akName))
	if err != nil {
		return nil, fmt.Errorf("decode AK name: %w", err)
	}
	if name.Digest == nil {
		return nil, fmt.Errorf("AK name has no digest (handle-based names not supported)")
	}

	credBlob, encSecret, err := credactivation.Generate(name.Digest, ekPubKey, symBlockSize, secret)
	if err != nil {
		return nil, fmt.Errorf("generate credential: %w", err)
	}

	if len(credBlob) > math.MaxUint16 {
		return nil, fmt.Errorf("credBlob too large for uint16 framing: %d bytes", len(credBlob))
	}

	// Wire format: uint16(len(credBlob)) [BE] || credBlob || encSecret
	out := make([]byte, 2+len(credBlob)+len(encSecret))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(credBlob)))
	copy(out[2:2+len(credBlob)], credBlob)
	copy(out[2+len(credBlob):], encSecret)

	v.logger.Info("credential generated", "credBlobSize", len(credBlob))
	return out, nil
}

func (v *realVerifier) ParseAKPublic(akParams []byte) ([]byte, []byte, error) {
	if len(akParams) > maxAKParamsSize {
		return nil, nil, fmt.Errorf("AK params too large: %d bytes (max %d)", len(akParams), maxAKParamsSize)
	}

	// attest.ParseAKPublic validates the TPM2B_PUBLIC structure (asymmetric params,
	// signing scheme) but doesn't expose the raw tpm2legacy.Public needed for Name
	// computation, so we call DecodePublic separately below.
	if _, err := attest.ParseAKPublic(akParams); err != nil {
		return nil, nil, fmt.Errorf("validate AK public: %w", err)
	}

	pub, err := tpm2legacy.DecodePublic(akParams)
	if err != nil {
		return nil, nil, fmt.Errorf("decode TPM2B_PUBLIC: %w", err)
	}

	name, err := pub.Name()
	if err != nil {
		return nil, nil, fmt.Errorf("compute AK name: %w", err)
	}

	nameBytes, err := name.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encode AK name: %w", err)
	}

	v.logger.Info("parsed AK public", "type", pub.Type, "nameAlg", pub.NameAlg)
	return akParams, nameBytes, nil
}

func (v *realVerifier) ExtractEKPublicKey(ekCertDER []byte) (crypto.PublicKey, error) {
	cert, err := x509.ParseCertificate(ekCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse EK cert: %w", err)
	}
	return cert.PublicKey, nil
}

func (v *realVerifier) EKFingerprint(ekCertDER []byte) string {
	h := sha256.Sum256(ekCertDER)
	return hex.EncodeToString(h[:])
}

func (v *realVerifier) ParseEKCert(ekCertDER []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(ekCertDER)
}

func (v *realVerifier) loadCertsFromDir(dir string, pool *x509.CertPool, label string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		v.logger.Warn("failed to read CA certs dir", "dir", dir, "label", label, "error", err)
		return 0
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".pem" && ext != ".crt" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			v.logger.Warn("failed to read CA cert", "file", entry.Name(), "error", err)
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			loaded++
		}
	}

	v.logger.Info("loaded CA certs", "label", label, "count", loaded, "dir", dir)
	return loaded
}
