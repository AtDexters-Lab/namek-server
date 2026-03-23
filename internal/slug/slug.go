package slug

import (
	"encoding/hex"
	"fmt"
	"regexp"
)

// crockford is the lowercase Crockford Base32 alphabet (no i, l, o, u).
const crockford = "0123456789abcdefghjkmnpqrstvwxyz"

var validRegex = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{20}$`)

// Derive computes a deterministic 20-char slug from an EK fingerprint.
// ekFingerprint is hex(sha256(ekCertDER)) — a 64-char hex string.
func Derive(ekFingerprint string) (string, error) {
	raw, err := hex.DecodeString(ekFingerprint)
	if err != nil || len(raw) < 13 {
		return "", fmt.Errorf("slug: invalid EK fingerprint")
	}
	return encodeN(raw[:13], 20), nil
}

// IsValid reports whether s is a well-formed slug.
func IsValid(s string) bool {
	return validRegex.MatchString(s)
}

// encodeN converts src bytes into nChars Crockford Base32 characters.
// Each character encodes 5 bits.
func encodeN(src []byte, nChars int) string {
	out := make([]byte, nChars)
	bits := uint64(0)
	bitsAvail := 0
	idx := 0
	for _, b := range src {
		bits = (bits << 8) | uint64(b)
		bitsAvail += 8
		for bitsAvail >= 5 && idx < nChars {
			bitsAvail -= 5
			out[idx] = crockford[(bits>>uint(bitsAvail))&0x1F]
			idx++
		}
	}
	return string(out)
}
