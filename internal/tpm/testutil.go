package tpm

import (
	"crypto"
	"crypto/x509"
)

// TestVerifier is a mock TPM verifier for testing.
type TestVerifier struct {
	VerifyEKCertFn      func(ekCertDER []byte) (*EKVerifyResult, error)
	VerifyQuoteFn       func(akPubKeyDER []byte, nonce []byte, quoteB64 string, pcrValues map[int][]byte) (*QuoteResult, error)
	MakeCredentialFn    func(ekPubKey crypto.PublicKey, akName []byte, secret []byte) ([]byte, error)
	ParseAKPublicFn     func(akParams []byte) ([]byte, []byte, error)
	ExtractEKPubKeyFn   func(ekCertDER []byte) (crypto.PublicKey, error)
	EKFingerprintFn     func(ekCertDER []byte) string
	EKPubFingerprintFn  func(ekPubDER []byte) string
	ParseEKCertFn       func(ekCertDER []byte) (*x509.Certificate, error)
}

func (t *TestVerifier) VerifyEKCert(ekCertDER []byte) (*EKVerifyResult, error) {
	if t.VerifyEKCertFn != nil {
		return t.VerifyEKCertFn(ekCertDER)
	}
	return &EKVerifyResult{
		IdentityClass:     IdentityClassUnverified,
		EKPubKey:          nil,
		IssuerFingerprint: "test-issuer-fp",
		IssuerSubject:     "CN=Test Issuer",
	}, nil
}

func (t *TestVerifier) VerifyQuote(akPubKeyDER []byte, nonce []byte, quoteB64 string, pcrValues map[int][]byte) (*QuoteResult, error) {
	if t.VerifyQuoteFn != nil {
		return t.VerifyQuoteFn(akPubKeyDER, nonce, quoteB64, pcrValues)
	}
	return &QuoteResult{PCRValues: pcrValues}, nil
}

func (t *TestVerifier) MakeCredential(ekPubKey crypto.PublicKey, akName []byte, secret []byte) ([]byte, error) {
	if t.MakeCredentialFn != nil {
		return t.MakeCredentialFn(ekPubKey, akName, secret)
	}
	// Return the secret as-is for testing (no encryption)
	return secret, nil
}

func (t *TestVerifier) ParseAKPublic(akParams []byte) ([]byte, []byte, error) {
	if t.ParseAKPublicFn != nil {
		return t.ParseAKPublicFn(akParams)
	}
	return akParams, []byte("test-ak-name"), nil
}

func (t *TestVerifier) ExtractEKPublicKey(ekCertDER []byte) (crypto.PublicKey, error) {
	if t.ExtractEKPubKeyFn != nil {
		return t.ExtractEKPubKeyFn(ekCertDER)
	}
	return nil, nil
}

func (t *TestVerifier) EKFingerprint(ekCertDER []byte) string {
	if t.EKFingerprintFn != nil {
		return t.EKFingerprintFn(ekCertDER)
	}
	return "test-fingerprint"
}

func (t *TestVerifier) EKPubFingerprint(ekPubDER []byte) string {
	if t.EKPubFingerprintFn != nil {
		return t.EKPubFingerprintFn(ekPubDER)
	}
	return "test-fingerprint"
}

func (t *TestVerifier) ParseEKCert(ekCertDER []byte) (*x509.Certificate, error) {
	if t.ParseEKCertFn != nil {
		return t.ParseEKCertFn(ekCertDER)
	}
	return &x509.Certificate{}, nil
}
