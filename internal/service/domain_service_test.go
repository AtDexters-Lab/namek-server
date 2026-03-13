package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDomain(t *testing.T) {
	baseDomain := "piccolospace.com"

	tests := []struct {
		name    string
		domain  string
		wantErr string
	}{
		{
			name:   "valid 3-label domain",
			domain: "app.example.com",
		},
		{
			name:   "valid 4-label domain",
			domain: "sub.app.example.com",
		},
		{
			name:   "valid domain with hyphens",
			domain: "my-app.example.com",
		},
		{
			name:   "valid domain with digits",
			domain: "app123.example.com",
		},
		{
			name:    "empty domain",
			domain:  "",
			wantErr: "domain must be 1-253 characters",
		},
		{
			name:    "too few labels (2)",
			domain:  "example.com",
			wantErr: "domain must have at least 3 labels",
		},
		{
			name:    "too few labels (1)",
			domain:  "com",
			wantErr: "domain must have at least 3 labels",
		},
		{
			name:    "IP address v4",
			domain:  "192.168.1.1",
			wantErr: "IP addresses are not allowed",
		},
		{
			name:    "IP address v6",
			domain:  "::1",
			wantErr: "IP addresses are not allowed",
		},
		{
			name:    "baseDomain subdomain",
			domain:  "app.piccolospace.com",
			wantErr: "cannot register subdomains of piccolospace.com",
		},
		{
			name:    "baseDomain itself",
			domain:  "piccolospace.com",
			wantErr: "domain must have at least 3 labels",
		},
		{
			name:    "label starts with hyphen",
			domain:  "-app.example.com",
			wantErr: "domain labels must not start or end with a hyphen",
		},
		{
			name:    "label ends with hyphen",
			domain:  "app-.example.com",
			wantErr: "domain labels must not start or end with a hyphen",
		},
		{
			name:    "empty label",
			domain:  "app..example.com",
			wantErr: "each domain label must be 1-63 characters",
		},
		{
			name:    "uppercase rejected",
			domain:  "App.Example.COM",
			wantErr: "domain labels must contain only lowercase letters",
		},
		{
			name:    "underscore rejected",
			domain:  "app_name.example.com",
			wantErr: "domain labels must contain only lowercase letters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomain(tt.domain, baseDomain)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateDomain_LongDomain(t *testing.T) {
	// 254 chars should fail
	long := ""
	for i := 0; i < 250; i++ {
		long += "a"
	}
	long += ".b.c"
	err := validateDomain(long, "example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "253 characters")
}
