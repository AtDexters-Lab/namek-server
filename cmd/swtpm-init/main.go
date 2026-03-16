// swtpm-init initializes software TPM state and CA certificates.
// Used by `make dev-deps` to prepare the swtpm environment.
// namek-server accepts software TPMs when tpm.allowSoftwareTPM is true.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AtDexters-Lab/namek-server/pkg/swtpm"
)

func main() {
	rootDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}
	stateDir := filepath.Join(rootDir, ".local", "swtpm")

	proc, err := swtpm.Start(context.Background(), stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "swtpm init: %v\n", err)
		os.Exit(1)
	}
	proc.Stop()

	fmt.Printf("swtpm state initialized: %s\n", stateDir)
	fmt.Printf("CA certs available at: %s\n", proc.CACertDir())
}
