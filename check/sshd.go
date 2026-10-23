package check

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/boxwarden/agent/finding"
)

// Drop-in, not sshd_config: Debian/Ubuntu include sshd_config.d first and the first value wins,
// so edits to sshd_config lose to e.g. 50-cloud-init.conf. "00-" sorts before everything.
const sshdDropIn = "/etc/ssh/sshd_config.d/00-hardening.conf"

const sshdApply = "sudo sshd -t && (sudo systemctl reload ssh || sudo systemctl reload sshd)" // "sshd" on RHEL

// Disabling passwords on a server without a working key locks you out.
const keysFirst = "FIRST add your key and check it works in a new session, keeping this one open: ssh-copy-id root@your-server. THEN "

// SSHD reads the effective config via `sshd -T` (resolves Include and defaults; needs root).
func SSHD() ([]finding.Finding, error) {
	out, err := exec.Command("sshd", "-T").Output()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, nil // no SSH server, nothing to harden
	}
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w (run as root)", err)
	}
	return sshdFindings(string(out), rootHasKeys("/"), rootLocked("/")), nil
}

func rootHasKeys(root string) bool {
	for line := range strings.SplitSeq(readFile(root, "root/.ssh/authorized_keys"), "\n") {
		if keyFingerprint(line) != "" {
			return true
		}
	}
	return false
}

// rootLocked is true when root has no usable password, so password logins as root can't succeed.
func rootLocked(root string) bool {
	for _, a := range accounts(root) {
		if a.name == "root" {
			return a.locked()
		}
	}
	return false
}

func sshdFindings(effective string, rootKeys, rootLocked bool) []finding.Finding {
	cfg := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(effective))
	for sc.Scan() {
		k, v, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		cfg[strings.ToLower(k)] = strings.ToLower(v)
	}
	passwords := cfg["passwordauthentication"] == "yes" || cfg["kbdinteractiveauthentication"] == "yes"
	disablePasswords := "add `PasswordAuthentication no` and `KbdInteractiveAuthentication no` to " + sshdDropIn + ", then: " + sshdApply

	var fs []finding.Finding
	if passwords && cfg["permitemptypasswords"] == "yes" {
		fs = append(fs, finding.Finding{
			ID: "ssh.empty-passwords", Severity: finding.Critical,
			Title: "SSH allows login with empty passwords",
			Fix:   "Add `PermitEmptyPasswords no` to " + sshdDropIn + ", then: " + sshdApply,
		})
	}
	if passwords && cfg["permitrootlogin"] == "yes" && !rootLocked {
		f := finding.Finding{
			ID: "ssh.root-password-login", Severity: finding.Critical,
			Title:  "Root can log in over SSH with a password",
			Detail: "Bots try root passwords on every public SSH server around the clock; one weak or leaked password is full control.",
			Fix:    keysFirst + "add `PermitRootLogin prohibit-password` and `PasswordAuthentication no` to " + sshdDropIn + ", then: " + sshdApply + "; and change the root password: passwd",
		}
		if !rootKeys {
			f.Detail += " root has no SSH keys, so every login uses this password."
		}
		fs = append(fs, f)
	}
	if passwords {
		f := finding.Finding{
			ID: "ssh.password-auth", Severity: finding.High,
			Title:  "SSH accepts passwords",
			Detail: "Password logins are brute-forced around the clock. Use keys only.",
			Fix:    keysFirst + disablePasswords,
		}
		fs = append(fs, f)
	}
	return fs
}
