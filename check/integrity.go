package check

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/boxwarden/agent/finding"
)

// Packages whose binaries rootkits replace: to hide (ps, ls, ss, netstat, find, lsof, top) or to steal
// logins (sshd, sudo, su, login, passwd, PAM). Only their bin, sbin and PAM module files are hashed.
var integrityPkgs = []string{
	"openssh-server", "openssh-client", "sudo", "login", "passwd", "util-linux", "procps", "coreutils",
	"findutils", "iproute2", "net-tools", "lsof", "bash", "dash", "cron", "libpam-modules", "libpam-modules-bin",
}

// Integrity compares system binaries with the MD5s dpkg recorded when it installed them. A root
// attacker can rewrite those lists too; this catches the many who don't bother.
func Integrity() ([]finding.Finding, error) { return integrity("/"), nil }

func integrity(root string) []finding.Finding {
	if dpkgBusy(root) {
		return nil // mid-upgrade new files and old MD5 lists disagree; the next scan checks
	}
	diverted := map[string]bool{} // files another package replaced on purpose (dpkg-divert)
	lines := strings.Split(readFile(root, "var/lib/dpkg/diversions"), "\n")
	for i := 0; i+2 < len(lines); i += 3 {
		diverted[strings.TrimPrefix(lines[i], "/")] = true
	}

	var fs []finding.Finding
	for _, pkg := range integrityPkgs {
		lists, _ := filepath.Glob(filepath.Join(root, "var/lib/dpkg/info", pkg+"*.md5sums"))
		for _, list := range lists {
			if name := filepath.Base(list); name != pkg+".md5sums" && !strings.HasPrefix(name, pkg+":") {
				continue // "login*" also matches "loginctl…"
			}
			for line := range strings.SplitSeq(readFile(root, rel(root, list)), "\n") {
				sum, path, ok := strings.Cut(line, "  ")
				p := "/" + path
				if !ok || diverted[path] || !strings.Contains(p, "/bin/") && !strings.Contains(p, "/sbin/") && !strings.Contains(p, "/security/") {
					continue
				}
				if got := md5File(filepath.Join(root, path)); got != "" && got != sum {
					fs = append(fs, finding.Finding{
						ID: "integrity.modified", Severity: finding.Critical,
						Title:  "System binary differs from its package: " + p + " (" + pkg + ")",
						Detail: "Its MD5 doesn't match what dpkg installed. Rootkits replace ps, ls, ss and sshd to hide themselves or to steal passwords. If you didn't rebuild or patch it yourself, assume compromise.",
						Fix:    "dpkg --verify " + pkg + "   # if you didn't change it: isolate the server, rebuild from a clean image, rotate all keys and passwords",
					})
				}
			}
		}
	}
	return fs
}

// md5File hashes a regular file, or returns "" if it is missing or not a regular file.
func md5File(path string) string {
	f := openRegular(func(flags int) (*os.File, error) { return os.OpenFile(path, flags, 0) })
	if f == nil {
		return ""
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// dpkgBusy: is apt or dpkg holding its lock right now? F_GETLK only asks, it takes nothing.
func dpkgBusy(root string) bool {
	f, err := os.Open(filepath.Join(root, "var/lib/dpkg/lock-frontend"))
	if err != nil {
		return false
	}
	defer f.Close()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
	return syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk) == nil && lk.Type != syscall.F_UNLCK
}
