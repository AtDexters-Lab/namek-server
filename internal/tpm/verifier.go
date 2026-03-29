package tpm

import (
	"crypto"
	"crypto/x509"
)

// EKVerifyResult contains the results of EK certificate verification.
type EKVerifyResult struct {
	IdentityClass     string          // "verified" | "unverified"
	EKPubKey          crypto.PublicKey
	IssuerFingerprint string // SHA-256 of issuer SubjectPublicKeyInfo (or issuer DN as fallback)
	IssuerSubject     string
	IssuerPubKeyDER   []byte
	IssuerIsCA        bool
	IssuerHasCertSign bool
}

// Verifier defines the TPM verification interface.
type Verifier interface {
	// VerifyEKCert verifies an EK certificate and returns the verification result
	// including identity class and issuer metadata for census tracking.
	VerifyEKCert(ekCertDER []byte) (*EKVerifyResult, error)

	// VerifyQuote verifies a TPM quote signed by the given AK public key.
	// nonce is the raw bytes that were passed to the TPM as qualifyingData.
	// When pcrValues is non-nil, the quote's PCR digest is verified against
	// the provided values. When nil, PCR validation is skipped.
	VerifyQuote(akPubKeyDER []byte, nonce []byte, quoteB64 string, pcrValues map[int][]byte) (*QuoteResult, error)

	// MakeCredential creates an encrypted credential challenge for the TPM.
	MakeCredential(ekPubKey crypto.PublicKey, akName []byte, secret []byte) ([]byte, error)

	// ParseAKPublic parses AK parameters and returns the AK public key DER and AK name.
	ParseAKPublic(akParams []byte) (akPubKeyDER []byte, akName []byte, err error)

	// ExtractEKPublicKey extracts the public key from an EK certificate.
	ExtractEKPublicKey(ekCertDER []byte) (crypto.PublicKey, error)

	// EKFingerprint computes SHA-256 fingerprint of an EK certificate.
	EKFingerprint(ekCertDER []byte) string

	// ParseEKCert parses a DER-encoded EK certificate.
	ParseEKCert(ekCertDER []byte) (*x509.Certificate, error)
}
