package model

import (
	"time"

	"github.com/google/uuid"
)

type TrustLevel string

const (
	TrustLevelStrong      TrustLevel = "strong"
	TrustLevelStandard    TrustLevel = "standard"
	TrustLevelProvisional TrustLevel = "provisional"
	TrustLevelSuspicious  TrustLevel = "suspicious"
	TrustLevelQuarantine  TrustLevel = "quarantine"
	TrustLevelSoftware    TrustLevel = "software"
)

type IssuerTier string

const (
	IssuerTierSeed              IssuerTier = "seed"
	IssuerTierCrowdCorroborated IssuerTier = "crowd_corroborated"
	IssuerTierUnverified        IssuerTier = "unverified"
)

type PCRGroup string

const (
	PCRGroupFirmware PCRGroup = "firmware"
	PCRGroupBoot     PCRGroup = "boot"
	PCRGroupOS       PCRGroup = "os"
)

// PCRGroupRegisters maps each PCR group to its constituent PCR indices.
var PCRGroupRegisters = map[PCRGroup][]int{
	PCRGroupFirmware: {0, 1},
	PCRGroupBoot:     {4, 5, 6, 7},
	PCRGroupOS:       {8, 9},
}

type EKIssuerCensus struct {
	ID                        uuid.UUID  `json:"id"`
	IssuerFingerprint         string     `json:"issuer_fingerprint"`
	IssuerSubject             string     `json:"issuer_subject"`
	IssuerPublicKeyDER        []byte     `json:"-"`
	IssuerIsCA                *bool      `json:"issuer_is_ca"`
	IssuerHasCertSign         *bool      `json:"issuer_has_certsign"`
	DeviceCount               int        `json:"device_count"`
	DistinctSubnetCount       int        `json:"distinct_subnet_count"`
	StructuralComplianceScore *float32   `json:"structural_compliance_score"`
	Tier                      IssuerTier `json:"tier"`
	FirstSeenAt               time.Time  `json:"first_seen_at"`
	LastSeenAt                time.Time  `json:"last_seen_at"`
	Flagged                   bool       `json:"flagged"`
	FlaggedReason             *string    `json:"flagged_reason,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
}

type EKIssuerObservation struct {
	ID                int64     `json:"id"`
	IssuerFingerprint string    `json:"issuer_fingerprint"`
	DeviceID          uuid.UUID `json:"device_id"`
	ClientIPSubnet    string    `json:"client_ip_subnet"`
	ObservedAt        time.Time `json:"observed_at"`
}

type PCRCensus struct {
	ID               uuid.UUID         `json:"id"`
	GroupingKey      string            `json:"grouping_key"`
	PCRGroup         PCRGroup          `json:"pcr_group"`
	PCRCompositeHash string            `json:"pcr_composite_hash"`
	PCRValues        map[string]string `json:"pcr_values"`
	DeviceCount      int               `json:"device_count"`
	IsMajority       bool              `json:"is_majority"`
	FirstSeenAt      time.Time         `json:"first_seen_at"`
	LastSeenAt       time.Time         `json:"last_seen_at"`
}

// PCRConsensusStatus represents the result of comparing a device's PCR values against the census.
type PCRConsensusStatus string

const (
	PCRConsensusMajority PCRConsensusStatus = "majority"
	PCRConsensusOutlier  PCRConsensusStatus = "outlier"
	PCRConsensusUnknown  PCRConsensusStatus = "unknown"
)
