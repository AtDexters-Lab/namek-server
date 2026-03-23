package identity

import "testing"

func TestDeviceID_Deterministic(t *testing.T) {
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	id1 := DeviceID(fp)
	id2 := DeviceID(fp)
	if id1 != id2 {
		t.Errorf("DeviceID not deterministic: %s != %s", id1, id2)
	}
}

func TestAccountID_Deterministic(t *testing.T) {
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	id1 := AccountID(fp)
	id2 := AccountID(fp)
	if id1 != id2 {
		t.Errorf("AccountID not deterministic: %s != %s", id1, id2)
	}
}

func TestDeviceID_AccountID_Different(t *testing.T) {
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	deviceID := DeviceID(fp)
	accountID := AccountID(fp)
	if deviceID == accountID {
		t.Errorf("DeviceID and AccountID should differ for same input: both = %s", deviceID)
	}
}

func TestDeviceID_DifferentInput(t *testing.T) {
	fp1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	fp2 := "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if DeviceID(fp1) == DeviceID(fp2) {
		t.Error("different fingerprints should produce different DeviceIDs")
	}
}

func TestAccountID_DifferentInput(t *testing.T) {
	fp1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	fp2 := "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if AccountID(fp1) == AccountID(fp2) {
		t.Error("different fingerprints should produce different AccountIDs")
	}
}
