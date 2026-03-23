package identity

import "github.com/google/uuid"

// Separate namespace UUIDs guarantee device_id != account_id even for the
// same EK fingerprint. WARNING: Changing either value invalidates all
// deterministic IDs and cached identity references. Never change them.
const DeviceNamespaceUUID = "a3e4b8c1-7f2d-4e6a-9b5c-d8f1e2a3b4c5"
const AccountNamespaceUUID = "b4f5c9d2-8a3e-5f7b-0c6d-e9f2a3b4c5d6"

var (
	deviceNS  = uuid.MustParse(DeviceNamespaceUUID)
	accountNS = uuid.MustParse(AccountNamespaceUUID)
)

// DeviceID derives a deterministic device UUID from an EK fingerprint.
func DeviceID(ekFingerprint string) uuid.UUID {
	return uuid.NewSHA1(deviceNS, []byte(ekFingerprint))
}

// AccountID derives a deterministic account UUID from the founding device's EK fingerprint.
func AccountID(ekFingerprint string) uuid.UUID {
	return uuid.NewSHA1(accountNS, []byte(ekFingerprint))
}
