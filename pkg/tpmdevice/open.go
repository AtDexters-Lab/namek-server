package tpmdevice

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// EK cert NVRAM index per TCG EK Credential Profile
const ekCertNVIndex = 0x01C00002

// ekPolicyDigest is the well-known SHA256 digest of PolicySecret(ENDORSEMENT).
var ekPolicyDigest = []byte{
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
	0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
	0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
	0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
}

var ekTemplate = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
	AuthPolicy: ekPolicyDigest,
	RSAParameters: &tpm2.RSAParams{
		Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
		KeyBits:   2048,
	},
}

var srkTemplate = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagNoDA | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagUserWithAuth,
	RSAParameters: &tpm2.RSAParams{
		Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
		KeyBits:   2048,
	},
}

var akTemplate = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagRestricted | tpm2.FlagSignerDefault | tpm2.FlagNoDA | tpm2.FlagUserWithAuth,
	RSAParameters: &tpm2.RSAParams{
		Sign:    &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
		KeyBits: 2048,
	},
}

type device struct {
	rw           io.ReadWriteCloser
	ekHandle     tpmutil.Handle
	akHandle     tpmutil.Handle
	persistentEK bool // true if using persistent EK handle (don't flush)
	ekCertDER    []byte
	akPubRaw     []byte // TPMT_PUBLIC bytes
}

// Open connects to a TPM at the given address and initializes EK + AK.
// addr is a Unix domain socket path (e.g. "/tmp/swtpm.sock" or "/dev/tpmrm0").
// For swtpm, use the Unix socket path returned by Process.Addr().
func Open(_ context.Context, addr string) (Device, error) {
	rw, err := tpmutil.OpenTPM(addr)
	if err != nil {
		return nil, fmt.Errorf("open tpm %s: %w", addr, err)
	}

	d := &device{rw: rw}
	if err := d.init(); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func (d *device) init() error {
	// 1. Try to use the persistent EK handle (0x81010001) created by swtpm_setup.
	// Fall back to creating a transient EK primary if it doesn't exist.
	const persistentEKHandle tpmutil.Handle = 0x81010001
	_, _, _, err := tpm2.ReadPublic(d.rw, persistentEKHandle)
	if err == nil {
		d.ekHandle = persistentEKHandle
		d.persistentEK = true
	} else {
		ekHandle, _, err := tpm2.CreatePrimary(d.rw, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", ekTemplate)
		if err != nil {
			return fmt.Errorf("create ek primary: %w", err)
		}
		d.ekHandle = ekHandle
	}

	// 2. Read EK cert from NVRAM
	ekCert, err := tpm2.NVReadEx(d.rw, tpmutil.Handle(ekCertNVIndex), tpm2.HandleOwner, "", 0)
	if err != nil {
		return fmt.Errorf("read ek cert from nvram (index 0x%x): %w", ekCertNVIndex, err)
	}
	d.ekCertDER = ekCert

	// 3. Create SRK primary
	srkHandle, _, err := tpm2.CreatePrimary(d.rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return fmt.Errorf("create srk primary: %w", err)
	}

	// 4. Create AK under SRK
	akPriv, akPub, _, _, _, err := tpm2.CreateKey(d.rw, srkHandle, tpm2.PCRSelection{}, "", "", akTemplate)
	if err != nil {
		tpm2.FlushContext(d.rw, srkHandle)
		return fmt.Errorf("create ak key: %w", err)
	}

	// 5. Load AK
	akHandle, _, err := tpm2.Load(d.rw, srkHandle, "", akPub, akPriv)
	if err != nil {
		tpm2.FlushContext(d.rw, srkHandle)
		return fmt.Errorf("load ak: %w", err)
	}
	d.akHandle = akHandle

	// 6. Store AK public bytes (TPMT_PUBLIC, no TPM2B size prefix)
	d.akPubRaw = akPub

	// 7. Flush SRK - no longer needed
	tpm2.FlushContext(d.rw, srkHandle)

	return nil
}

func (d *device) EKCertDER() ([]byte, error) {
	if d.ekCertDER == nil {
		return nil, fmt.Errorf("ek cert not available")
	}
	out := make([]byte, len(d.ekCertDER))
	copy(out, d.ekCertDER)
	return out, nil
}

func (d *device) AKPublic() ([]byte, error) {
	if d.akPubRaw == nil {
		return nil, fmt.Errorf("ak public not available")
	}
	out := make([]byte, len(d.akPubRaw))
	copy(out, d.akPubRaw)
	return out, nil
}

func (d *device) ActivateCredential(encCredential []byte) ([]byte, error) {
	// Parse outer wire format: uint16(credBlobLen) || credBlob || encSecret
	if len(encCredential) < 4 {
		return nil, fmt.Errorf("encCredential too short: %d bytes", len(encCredential))
	}
	credBlobLen := int(binary.BigEndian.Uint16(encCredential[:2]))
	if 2+credBlobLen > len(encCredential) {
		return nil, fmt.Errorf("credBlob length %d exceeds data size %d", credBlobLen, len(encCredential)-2)
	}
	credBlob := encCredential[2 : 2+credBlobLen]
	encSecret := encCredential[2+credBlobLen:]

	// credBlob and encSecret from credactivation.Generate() include TPM2B size
	// prefixes. ActivateCredentialUsingAuth's tpmutil.Pack adds its own U16 prefix,
	// so we must strip the existing prefix to avoid double-framing.
	if len(credBlob) < 2 || len(encSecret) < 2 {
		return nil, fmt.Errorf("credBlob (%d) or encSecret (%d) too short for TPM2B prefix", len(credBlob), len(encSecret))
	}
	rawCredBlob := credBlob[2:]
	rawEncSecret := encSecret[2:]

	// Create policy session for EK authorization
	session, _, err := tpm2.StartAuthSession(d.rw,
		tpm2.HandleNull, tpm2.HandleNull,
		make([]byte, 16), nil,
		tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("start auth session: %w", err)
	}
	defer tpm2.FlushContext(d.rw, session)

	// PolicySecret(TPM_RH_ENDORSEMENT)
	if _, _, err := tpm2.PolicySecret(d.rw, tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		session, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("policy secret: %w", err)
	}

	// Auth commands: AK=password, EK=policy
	auths := []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		{Session: session, Attributes: tpm2.AttrContinueSession},
	}

	secret, err := tpm2.ActivateCredentialUsingAuth(d.rw, auths, d.akHandle, d.ekHandle, rawCredBlob, rawEncSecret)
	if err != nil {
		return nil, fmt.Errorf("activate credential: %w", err)
	}
	return secret, nil
}

func (d *device) Quote(nonce string) (string, error) {
	attest, sig, err := tpm2.QuoteRaw(d.rw, d.akHandle, "", "",
		[]byte(nonce),
		tpm2.PCRSelection{Hash: tpm2.AlgSHA256},
		tpm2.AlgNull)
	if err != nil {
		return "", fmt.Errorf("tpm quote: %w", err)
	}

	// Wire format: uint32(attestLen) || TPMS_ATTEST || TPMT_SIGNATURE
	buf := make([]byte, 4+len(attest)+len(sig))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(attest)))
	copy(buf[4:], attest)
	copy(buf[4+len(attest):], sig)
	return base64.StdEncoding.EncodeToString(buf), nil
}

func (d *device) Close() error {
	if d.akHandle != 0 {
		tpm2.FlushContext(d.rw, d.akHandle)
	}
	if d.ekHandle != 0 && !d.persistentEK {
		tpm2.FlushContext(d.rw, d.ekHandle)
	}
	if d.rw != nil {
		return d.rw.Close()
	}
	return nil
}
