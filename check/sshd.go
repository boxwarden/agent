package check

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

const sshdFix = "sudo sshd -t && sudo systemctl reload ssh"

// SSHD reads the effective config via `sshd -T` (resolves Include and defaults; needs root).
func SSHD() ([]finding.Finding, error) {
	out, err := exec.Command("sshd", "-T").Output()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, nil // no SSH server, nothing to harden
	}
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w (run as root)", err)
	}
	return sshdFindings(string(out)), nil
}

func sshdFindings(effective string) []finding.Finding {
	cfg := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(effective))
	for sc.Scan() {
		k, v, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		cfg[strings.ToLower(k)] = strings.ToLower(v)
	}

	var fs []finding.Finding
	if cfg["permitemptypasswords"] == "yes" {
		fs = append(fs, finding.Finding{
			ID: "ssh.empty-passwords", Severity: finding.Critical,
			Title: "SSH allows login with empty passwords",
			Fix:   "Set `PermitEmptyPasswords no` in /etc/ssh/sshd_config, then: " + sshdFix,
		})
	}
	if cfg["passwordauthentication"] == "yes" || cfg["kbdinteractiveauthentication"] == "yes" {
		fs = append(fs, finding.Finding{
			ID: "ssh.password-auth", Severity: finding.High,
			Title:  "SSH accepts passwords",
			Detail: "Password logins are brute-forced around the clock. Use keys only.",
			Fix:    "Set `PasswordAuthentication no` and `KbdInteractiveAuthentication no` in /etc/ssh/sshd_config, then: " + sshdFix,
		})
	}
	if cfg["permitrootlogin"] == "yes" {
		fs = append(fs, finding.Finding{
			ID: "ssh.root-password-login", Severity: finding.High,
			Title: "SSH allows root login with a password",
			Fix:   "Set `PermitRootLogin prohibit-password` (or `no`) in /etc/ssh/sshd_config, then: " + sshdFix,
		})
	}
	return fs
}
