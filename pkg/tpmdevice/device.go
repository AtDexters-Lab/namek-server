package tpmdevice

// Device abstracts TPM operations needed for attestation.
// Callers manage the TPM lifecycle externally; Device only holds the connection.
type Device interface {
	// EKCertDER returns the DER-encoded EK certificate from TPM NVRAM.
	// Returns (nil, nil) when the TPM has no EK certificate provisioned
	// (e.g. VirtualBox vTPM). Callers should fall back to EKPublicDER().
	EKCertDER() ([]byte, error)

	// EKPublicDER returns the PKIX DER-encoded EK public key.
	// Always available regardless of whether the TPM has an EK certificate.
	EKPublicDER() ([]byte, error)

	// AKPublic returns the raw TPMT_PUBLIC bytes from CreateKey.
	// Server's ParseAKPublic calls tpm2legacy.DecodePublic() which expects this format.
	AKPublic() ([]byte, error)

	// ActivateCredential decrypts the server's credential challenge.
	// Input: raw wire bytes (uint16(credBlobLen) || credBlob || encSecret)
	// Output: decrypted 32-byte secret
	ActivateCredential(encCredential []byte) ([]byte, error)

	// Quote generates a TPM quote signed by the AK.
	// nonce is passed directly to the TPM as qualifyingData — callers must
	// decode any transport encoding (hex, base64) before calling.
	// Max 32 bytes to fit TPM2B_DATA on SHA-256-only TPMs.
	// Returns base64-encoded wire format: uint32(quoteLen) || TPMS_ATTEST || TPMT_SIGNATURE
	Quote(nonce []byte) (string, error)

	// QuoteOverData generates a TPM quote using sha256(data) as the nonce.
	// Used for voucher signing where the "nonce" is a deterministic hash of the payload.
	QuoteOverData(data []byte) (string, error)

	// Close releases TPM handles (EK, AK) and closes the connection.
	Close() error
}
