package swtpm

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// Process manages an swtpm subprocess.
type Process struct {
	cmd      *exec.Cmd
	logFile  *os.File
	stateDir string
	sockPath string // Unix domain socket path
	stopOnce sync.Once
}

// Start launches an swtpm instance. If stateDir has no TPM state,
// runs swtpm_setup first to initialize state and create EK cert.
// Context controls the startup timeout (not the process lifetime).
func Start(ctx context.Context, stateDir string) (*Process, error) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		return nil, fmt.Errorf("swtpm binary not found: install with 'apt install swtpm swtpm-tools'")
	}
	if _, err := exec.LookPath("swtpm_setup"); err != nil {
		return nil, fmt.Errorf("swtpm_setup binary not found: install with 'apt install swtpm-tools'")
	}

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	// Check if TPM state already exists
	if !tpmStateExists(stateDir) {
		if err := writeSetupConfig(stateDir); err != nil {
			return nil, fmt.Errorf("write swtpm config: %w", err)
		}
		if err := runSetup(ctx, stateDir); err != nil {
			return nil, fmt.Errorf("swtpm_setup: %w", err)
		}
	}

	sockPath := filepath.Join(stateDir, "swtpm.sock")
	ctrlSockPath := filepath.Join(stateDir, "swtpm-ctrl.sock")

	// Remove stale sockets from a previous run
	os.Remove(sockPath)
	os.Remove(ctrlSockPath)

	// Start swtpm
	logFile, err := os.Create(filepath.Join(stateDir, "swtpm.log"))
	if err != nil {
		return nil, fmt.Errorf("create swtpm log: %w", err)
	}

	// Do NOT use exec.CommandContext here — the process must outlive the
	// startup context. Stop() handles graceful shutdown independently.
	cmd := exec.Command("swtpm", "socket",
		"--tpm2",
		"--tpmstate", fmt.Sprintf("dir=%s", stateDir),
		"--server", fmt.Sprintf("type=unixio,path=%s", sockPath),
		"--ctrl", fmt.Sprintf("type=unixio,path=%s", ctrlSockPath),
		"--flags", "startup-clear",
	)
	cmd.Stderr = logFile
	cmd.Stdout = logFile

	if runtime.GOOS == "linux" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start swtpm: %w", err)
	}

	p := &Process{
		cmd:      cmd,
		logFile:  logFile,
		stateDir: stateDir,
		sockPath: sockPath,
	}

	// Wait for Unix socket to become reachable
	if err := waitForSocket(ctx, sockPath); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		logFile.Close()
		return nil, fmt.Errorf("swtpm not reachable: %w", err)
	}

	return p, nil
}

// Addr returns the Unix socket path for TPM commands.
func (p *Process) Addr() string {
	return p.sockPath
}

// CACertDir returns the path containing swtpm's local CA certificates.
// These certs must be trusted by namek-server's softwareCACertsDir.
func (p *Process) CACertDir() string {
	// The localca config directs CA output to stateDir/localca/
	return filepath.Join(p.stateDir, "localca")
}

// Stop gracefully shuts down the swtpm process and cleans up resources.
// Safe to call concurrently or multiple times.
func (p *Process) Stop() error {
	var err error
	p.stopOnce.Do(func() {
		if p.cmd == nil || p.cmd.Process == nil {
			return
		}
		p.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- p.cmd.Wait() }()

		select {
		case <-time.After(5 * time.Second):
			p.cmd.Process.Kill()
			err = <-done
		case e := <-done:
			err = e
		}

		if p.logFile != nil {
			p.logFile.Close()
		}
	})
	return err
}

func tpmStateExists(stateDir string) bool {
	// swtpm creates tpm2-00.permall as the primary state file
	_, err := os.Stat(filepath.Join(stateDir, "tpm2-00.permall"))
	return err == nil
}

// writeSetupConfig creates swtpm config files that direct the local CA
// output into stateDir/localca/ instead of the default ~/.config/swtpm-localca/.
func writeSetupConfig(stateDir string) error {
	localcaDir := filepath.Join(stateDir, "localca")
	if err := os.MkdirAll(localcaDir, 0700); err != nil {
		return fmt.Errorf("create localca dir: %w", err)
	}

	// swtpm_setup config: tells it where to find the cert creation tool config
	setupConf := fmt.Sprintf(
		"create_certs_tool=/usr/bin/swtpm_localca\ncreate_certs_tool_config=%s\ncreate_certs_tool_options=%s\n",
		filepath.Join(stateDir, "swtpm-localca.conf"),
		filepath.Join(stateDir, "swtpm-localca.options"),
	)
	if err := os.WriteFile(filepath.Join(stateDir, "swtpm_setup.conf"), []byte(setupConf), 0600); err != nil {
		return err
	}

	// localca config: tells swtpm_localca where to store signing key/cert.
	// signingkey/issuercert are the *intermediate* CA (auto-created on first run).
	// The root CA (swtpm-localca-rootca-{privkey,cert}.pem) is generated alongside
	// and signs the intermediate. certserial tracks certificate serial numbers.
	localcaConf := fmt.Sprintf(
		"statedir = %s\nsigningkey = %s\nissuercert = %s\ncertserial = %s\n",
		localcaDir,
		filepath.Join(localcaDir, "signkey.pem"),
		filepath.Join(localcaDir, "issuercert.pem"),
		filepath.Join(localcaDir, "certserial"),
	)
	if err := os.WriteFile(filepath.Join(stateDir, "swtpm-localca.conf"), []byte(localcaConf), 0600); err != nil {
		return err
	}

	// localca options: platform metadata
	localcaOpts := "--platform-manufacturer swtpm\n--platform-version 2.1\n--platform-model swtpm\n"
	return os.WriteFile(filepath.Join(stateDir, "swtpm-localca.options"), []byte(localcaOpts), 0600)
}

func runSetup(ctx context.Context, stateDir string) error {
	cmd := exec.CommandContext(ctx, "swtpm_setup",
		"--tpm2",
		"--tpmstate", stateDir,
		"--config", filepath.Join(stateDir, "swtpm_setup.conf"),
		"--create-ek-cert",
		"--create-platform-cert",
		"--logfile", filepath.Join(stateDir, "setup.log"),
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if logData, readErr := os.ReadFile(filepath.Join(stateDir, "setup.log")); readErr == nil {
			return fmt.Errorf("%w\nsetup log:\n%s", err, string(logData))
		}
		return err
	}
	return nil
}

func waitForSocket(ctx context.Context, sockPath string) error {
	deadline := time.After(10 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for socket %s", sockPath)
		default:
			conn, err := net.Dial("unix", sockPath)
			if err == nil {
				conn.Close()
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
