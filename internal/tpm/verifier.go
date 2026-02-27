package tpm

import (
	"crypto"
	"crypto/x509"
)

// Verifier defines the TPM verification interface.
type Verifier interface {
	// VerifyEKCert verifies an EK certificate and returns the identity class.
	VerifyEKCert(ekCertDER []byte) (identityClass string, ekPubKey crypto.PublicKey, err error)

	// VerifyQuote verifies a TPM quote signed by the given AK public key.
	VerifyQuote(akPubKeyDER []byte, nonce string, quoteB64 string) error

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
