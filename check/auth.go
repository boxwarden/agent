package check

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/boxwarden/agent/finding"
)

type account struct {
	name, uid, home, shell string
	hash                   string // from /etc/shadow; "" means no password at all
	hasShadow              bool
}

// loginShell is false for accounts that can't get a shell (services, locked users).
func (a account) loginShell() bool {
	return !strings.HasSuffix(a.shell, "nologin") && !strings.HasSuffix(a.shell, "false") && a.shell != "/bin/sync"
}

// locked accounts have no usable password: "!..." (passwd -l), "*" or "!!" (never set).
func (a account) locked() bool {
	return a.hasShadow && (strings.HasPrefix(a.hash, "!") || strings.HasPrefix(a.hash, "*"))
}

func accounts(root string) []account {
	shadow := map[string]string{}
	for line := range strings.SplitSeq(readFile(root, "etc/shadow"), "\n") {
		if f := strings.Split(line, ":"); len(f) >= 2 {
			shadow[f[0]] = f[1] // only the hash's shape is used; it never leaves the host
		}
	}
	var out []account
	for line := range strings.SplitSeq(readFile(root, "etc/passwd"), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		a := account{name: f[0], uid: f[2], home: f[5], shell: f[6]}
		a.hash, a.hasShadow = shadow[f[0]]
		if f[1] != "x" && !a.hasShadow { // password kept in passwd itself (no shadow)
			a.hash, a.hasShadow = f[1], true
		}
		out = append(out, a)
	}
	return out
}

// Auth finds accounts that let someone in without the owner's say: a second root, no password,
// SSH keys planted in service accounts.
func Auth() ([]finding.Finding, error) {
	return auth("/"), nil
}

func auth(root string) []finding.Finding {
	var fs []finding.Finding
	uidMin := loginUIDMin(root)
	for _, a := range accounts(root) {
		if a.uid == "0" && a.name != "root" {
			fs = append(fs, finding.Finding{
				ID: "auth.uid0", Severity: finding.Critical,
				Title:  "Account " + a.name + " has UID 0: it is root under another name",
				Detail: "Attackers add a UID 0 account as a backdoor that survives a root password change. shell=" + a.shell,
				Fix:    "If you didn't create it, assume compromise: isolate the server and rebuild. To remove it: sudo userdel " + a.name,
			})
		}
		if a.hasShadow && a.hash == "" && a.loginShell() {
			fs = append(fs, finding.Finding{
				ID: "auth.empty-password", Severity: finding.Critical,
				Title:  "Account " + a.name + " has no password",
				Detail: "Anything that accepts passwords (console, su, SSH if PermitEmptyPasswords is on) lets anyone in as " + a.name + ".",
				Fix:    "sudo passwd -l " + a.name + "   # lock it; or set one: sudo passwd " + a.name,
			})
		}
		uid, _ := strconv.Atoi(a.uid)
		if a.uid == "0" || uid >= uidMin && a.loginShell() {
			continue // people: their keys are tracked by the ioc baseline
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			path := filepath.Join(a.home, ".ssh", name)
			n := 0
			for line := range strings.SplitSeq(readFile(root, path), "\n") {
				if keyFingerprint(line) != "" && !keyRestricted(line) {
					n++
				}
			}
			if n == 0 {
				continue
			}
			fs = append(fs, finding.Finding{
				ID: "auth.service-account-key", Severity: finding.High,
				Title:  "SSH key in service account " + a.name + ": " + path,
				Detail: strconv.Itoa(n) + " unrestricted key(s). Service accounts (web server, database, redis) never need SSH logins; exploits of those services plant keys exactly here.",
				Fix:    "If you didn't add it, assume that service was breached: sudo cat " + path + "; then remove the key and rebuild",
			})
		}
	}
	return fs
}

// keyRestricted is true for keys pinned to one command (git, borg, rsync): they can't open a shell.
func keyRestricted(line string) bool {
	opts, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	if strings.HasPrefix(opts, "ssh-") || strings.HasPrefix(opts, "ecdsa-") || strings.HasPrefix(opts, "sk-") {
		return false
	}
	return strings.Contains(opts, "command=") || strings.HasPrefix(opts, "restrict") || strings.Contains(opts, ",restrict")
}

// loginUIDMin is where human accounts start (UID_MIN in /etc/login.defs, 1000 almost everywhere).
func loginUIDMin(root string) int {
	for line := range strings.SplitSeq(readFile(root, "etc/login.defs"), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "UID_MIN" {
			if n, err := strconv.Atoi(f[1]); err == nil {
				return n
			}
		}
	}
	return 1000
}
