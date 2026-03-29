package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
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
	"time"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/google/go-attestation/attest"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
)

type realVerifier struct {
	hardwareCAs *x509.CertPool
	logger      *slog.Logger
}

func NewVerifier(cfg config.TPMConfig, logger *slog.Logger) (Verifier, error) {
	v := &realVerifier{
		hardwareCAs: x509.NewCertPool(),
		logger:      logger,
	}

	loaded := 0
	if cfg.TrustedCACertsDir != "" {
		loaded += v.loadCertsFromDir(cfg.TrustedCACertsDir, v.hardwareCAs, "operator")
	}
	if cfg.SeedBundleDir != "" {
		loaded += v.loadCertsFromDir(cfg.SeedBundleDir, v.hardwareCAs, "seed-bundle")
	}

	if loaded == 0 {
		logger.Warn("no TPM CA certificates loaded: all devices will be classified as unverified")
	}

	if cfg.AllowSoftwareTPM {
		logger.Warn("allowSoftwareTPM is deprecated and has no effect; unverifiable EK certs are always accepted as unverified")
	}
	logger.Info("tpm verifier initialized", "hardwareCAs", loaded, "allowSoftwareTPM", cfg.AllowSoftwareTPM)
	return v, nil
}

// trimDERTrailingData extracts the first complete ASN.1 element from der,
// stripping any trailing bytes. Some TPM manufacturers ship EK certificates
// with trailing padding after the DER structure; Go's x509.ParseCertificate
// rejects these with "x509: trailing data".
//
// Returns (trimmedBytes, true) if trailing data was stripped, or
// (originalBytes, false) if the input was already clean or unparseable.
func trimDERTrailingData(der []byte) ([]byte, bool) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) == 0 {
		return der, false
	}
	return raw.FullBytes, true
}

// parseEKCertLenient parses a DER-encoded X.509 certificate, tolerating
// trailing bytes after the ASN.1 SEQUENCE structure.
func (v *realVerifier) parseEKCertLenient(der []byte) (*x509.Certificate, error) {
	_, didTrim := trimDERTrailingData(der)
	if didTrim {
		v.logger.Warn("stripped trailing data from EK certificate DER",
			"originalLen", len(der))
	}
	return parseEKCertClean(der)
}

func (v *realVerifier) VerifyEKCert(ekCertDER []byte) (*EKVerifyResult, error) {
	cert, err := v.parseEKCertLenient(ekCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse EK cert: %w", err)
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

	result := &EKVerifyResult{
		EKPubKey:      cert.PublicKey,
		IssuerSubject: cert.Issuer.String(),
	}

	// Compute issuer fingerprint from issuer DN DER as fallback.
	// If we verify against hardwareCAs, we'll upgrade to SubjectPublicKeyInfo.
	issuerDNHash := sha256.Sum256(cert.RawIssuer)
	result.IssuerFingerprint = hex.EncodeToString(issuerDNHash[:])

	// EK certs typically lack ExtKeyUsageServerAuth (or have TPM-specific OIDs),
	// so we use ExtKeyUsageAny to avoid rejecting valid certs.
	ekVerifyOpts := func(roots *x509.CertPool) x509.VerifyOptions {
		return x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
	}

	// Try hardware CA pool first
	if chains, err := cert.Verify(ekVerifyOpts(v.hardwareCAs)); err == nil {
		result.IdentityClass = IdentityClassVerified
		// Extract issuer metadata from the verified chain
		if len(chains) > 0 && len(chains[0]) > 1 {
			issuer := chains[0][1]
			spkiHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
			result.IssuerFingerprint = hex.EncodeToString(spkiHash[:])
			result.IssuerPubKeyDER = issuer.RawSubjectPublicKeyInfo
			result.IssuerIsCA = issuer.IsCA
			result.IssuerHasCertSign = issuer.KeyUsage&x509.KeyUsageCertSign != 0
		}
		return result, nil
	}

	// EK cert not verifiable against trusted CAs — classify as unverified hardware.
	// Credential activation will prove real TPM possession regardless.
	result.IdentityClass = IdentityClassUnverified
	return result, nil
}

// ComputeStructuralCompliance scores an EK certificate against TCG profile expectations.
// Returns a score from 0.0 to 1.0 (5 checks, each worth 0.2).
func ComputeStructuralCompliance(cert *x509.Certificate) float32 {
	var score float32

	// Check 1: EKU — no ServerAuth/ClientAuth; may have TPM-specific OID or no EKU
	hasServerAuth := false
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth && !hasClientAuth {
		score += 0.2
	}

	// Check 2: SAN contains TPM manufacturer info (DirectoryName with OIDs 2.23.133.2.*)
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTPMManufacturer := asn1.ObjectIdentifier{2, 23, 133, 2}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSAN) {
			// Check raw SAN extension for TPM manufacturer OIDs
			if containsOIDPrefix(ext.Value, oidTPMManufacturer) {
				score += 0.2
			}
			break
		}
	}

	// Check 3: Key type and size — RSA-2048 or ECC P-256
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() == 2048 {
			score += 0.2
		}
	case *ecdsa.PublicKey:
		if pub.Curve == elliptic.P256() {
			score += 0.2
		}
	}

	// Check 4: Certificate validity period >= 10 years
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity >= 10*365*24*time.Hour {
		score += 0.2
	}

	// Check 5: Basic Constraints — IsCA must be false
	if !cert.IsCA {
		score += 0.2
	}

	return score
}

// containsOIDPrefix checks if raw ASN.1 data contains an OID with the given prefix.
// This is a best-effort check on the raw SAN extension bytes.
func containsOIDPrefix(raw []byte, prefix asn1.ObjectIdentifier) bool {
	// Encode the prefix OID to its DER byte representation for searching
	prefixDER, err := asn1.Marshal(prefix)
	if err != nil {
		return false
	}
	// The marshalled form includes tag+length, skip to the value portion
	if len(prefixDER) < 2 {
		return false
	}
	prefixBytes := prefixDER[2:] // skip tag (0x06) and length byte
	return bytes.Contains(raw, prefixBytes)
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
// When pcrValues is non-nil, the quote's PCR digest is verified against
// the provided values. When nil, only the signature and nonce are checked.
//
// Wire format for quoteB64 (after base64 decode):
//
//	uint32(quoteLen) [big-endian] || TPMS_ATTEST || TPMT_SIGNATURE
func (v *realVerifier) VerifyQuote(akPubKeyDER []byte, nonce []byte, quoteB64 string, pcrValues map[int][]byte) (*QuoteResult, error) {
	akPub, err := attest.ParseAKPublic(akPubKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse AK public: %w", err)
	}

	// Pre-check base64 string length to avoid allocating oversized buffers.
	// Base64 encodes 3 bytes as 4 chars, so decoded size ≈ len*3/4.
	if len(quoteB64) > maxQuoteSize*2 {
		return nil, fmt.Errorf("quote base64 string too large: %d chars", len(quoteB64))
	}

	data, err := base64.StdEncoding.DecodeString(quoteB64)
	if err != nil {
		return nil, fmt.Errorf("decode quote base64: %w", err)
	}
	if len(data) > maxQuoteSize {
		return nil, fmt.Errorf("quote data exceeds max size (%d > %d)", len(data), maxQuoteSize)
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("quote data too short: %d bytes", len(data))
	}

	ql := int(binary.BigEndian.Uint32(data[0:4]))
	if ql+4 > len(data) {
		return nil, fmt.Errorf("quote length exceeds available data: %d + 4 header > %d total", ql, len(data))
	}
	if len(data)-4-ql <= 0 {
		return nil, fmt.Errorf("signature portion is empty (quote %d bytes, total %d bytes)", ql, len(data))
	}

	quoteBytes := data[4 : 4+ql]
	sigBytes := data[4+ql:]

	// Build PCR list for verification when values are provided
	var pcrs []attest.PCR
	if pcrValues != nil {
		pcrs = make([]attest.PCR, 0, len(pcrValues))
		for idx, digest := range pcrValues {
			if len(digest) != 32 {
				return nil, fmt.Errorf("PCR %d digest length %d, expected 32 (SHA-256)", idx, len(digest))
			}
			pcrs = append(pcrs, attest.PCR{
				Index:     idx,
				Digest:    digest,
				DigestAlg: crypto.SHA256,
			})
		}
	}

	if err := akPub.Verify(attest.Quote{Quote: quoteBytes, Signature: sigBytes}, pcrs, nonce); err != nil {
		v.logger.Warn("quote verification failed", "error", err)
		return nil, fmt.Errorf("verify quote: %w", err)
	}

	v.logger.Debug("quote verification succeeded", "pcrCount", len(pcrValues))
	return &QuoteResult{PCRValues: pcrValues}, nil
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
	cert, err := v.parseEKCertLenient(ekCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse EK cert: %w", err)
	}
	return cert.PublicKey, nil
}

// EKFingerprint extracts the public key from the EK certificate and computes
// sha256(PKIX DER of public key). This produces the same fingerprint as
// EKPubFingerprint for the same underlying EK, ensuring identity consistency
// regardless of whether the device enrolls with cert or pubkey.
func (v *realVerifier) EKFingerprint(ekCertDER []byte) string {
	cert, err := v.parseEKCertLenient(ekCertDER)
	if err != nil {
		// Fallback: hash normalized cert DER. This breaks fingerprint unification
		// with EKPubFingerprint, so log at error level for operator visibility.
		v.logger.Error("EKFingerprint: cert parse failed, falling back to cert DER hash (fingerprint will not match pubkey path)", "error", err)
		normalized, _ := trimDERTrailingData(ekCertDER)
		h := sha256.Sum256(normalized)
		return hex.EncodeToString(h[:])
	}
	pkixDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		v.logger.Error("EKFingerprint: PKIX marshal failed, falling back to cert DER hash (fingerprint will not match pubkey path)", "error", err)
		normalized, _ := trimDERTrailingData(ekCertDER)
		h := sha256.Sum256(normalized)
		return hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(pkixDER)
	return hex.EncodeToString(h[:])
}

// EKPubFingerprint computes sha256(PKIX DER of EK public key).
// Used when no EK certificate is available. Produces the same fingerprint
// as EKFingerprint for the same underlying EK.
func (v *realVerifier) EKPubFingerprint(ekPubDER []byte) string {
	h := sha256.Sum256(ekPubDER)
	return hex.EncodeToString(h[:])
}

func (v *realVerifier) ParseEKCert(ekCertDER []byte) (*x509.Certificate, error) {
	return v.parseEKCertLenient(ekCertDER)
}

// ParseEKCertForCompliance parses a DER-encoded EK certificate for structural compliance scoring.
func ParseEKCertForCompliance(ekCertDER []byte) (*x509.Certificate, error) {
	return parseEKCertClean(ekCertDER)
}

// parseEKCertClean parses a DER cert with trailing data tolerance (shared logic).
func parseEKCertClean(der []byte) (*x509.Certificate, error) {
	trimmed, _ := trimDERTrailingData(der)
	return x509.ParseCertificate(trimmed)
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
