package check

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

// Snapshot is what "normal" looks like on a host: category -> item -> fingerprint.
// Names and hashes only, never file contents (ADR-0002).
type Snapshot map[string]map[string]string

const BaselinePath = "/var/lib/heimdall/baseline.json"

// Files attackers use for persistence and privilege. /etc/systemd/system is walked separately.
var watchedGlobs = []string{
	"etc/sudoers", "etc/sudoers.d/*",
	"etc/crontab", "etc/cron.d/*", "etc/cron.hourly/*", "etc/cron.daily/*", "etc/cron.weekly/*", "etc/cron.monthly/*",
	"var/spool/cron/crontabs/*",
	"etc/ld.so.preload", "etc/rc.local", "etc/profile.d/*",
}

// ponytail: SUID walk doesn't detect mount boundaries; this skip list keeps it sane on Docker hosts.
var suidSkip = map[string]bool{"/proc": true, "/sys": true, "/var/lib/docker": true, "/var/lib/containerd": true, "/snap": true}

var iocMeta = map[string]struct {
	sev  finding.Severity
	what string
}{
	"user":        {finding.High, "Login-capable user"},
	"ssh-key":     {finding.High, "SSH authorized key"},
	"sudo-member": {finding.High, "sudo/admin/docker group member"},
	"file":        {finding.High, "Cron/systemd/sudoers/preload file"},
	"suid":        {finding.High, "SUID binary"},
	"port":        {finding.Medium, "Listening port"},
}

const iocFix = "If you didn't make this change, assume compromise: isolate the server, rotate all keys and passwords, rebuild from a clean image. If you did: sudo heimdall baseline"

// IOC compares the host against the saved baseline and adds live indicators that need no baseline.
func IOC() ([]finding.Finding, error) {
	fs := Live("/")
	base, err := LoadBaseline(BaselinePath)
	if errors.Is(err, os.ErrNotExist) {
		return append(fs, finding.Finding{
			ID: "ioc.no-baseline", Severity: finding.Medium,
			Title: "No baseline yet: new users, keys, cron jobs and ports are not tracked",
			Fix:   "sudo heimdall baseline   # then review its output",
		}), nil
	}
	if err != nil {
		return nil, err
	}
	return append(fs, Diff(base, Collect("/"))...), nil
}

func LoadBaseline(path string) (Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	return s, json.Unmarshal(b, &s)
}

func SaveBaseline(path string, s Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// Diff reports items added or changed since base. Removals are not alarming and are ignored.
func Diff(base, cur Snapshot) []finding.Finding {
	var fs []finding.Finding
	for cat, items := range cur {
		meta := iocMeta[cat]
		for k, v := range items {
			old, seen := base[cat][k]
			if seen && old == v {
				continue
			}
			sev, verb := meta.sev, "added"
			if seen {
				verb = "changed"
			}
			if cat == "user" && strings.HasPrefix(v, "uid=0 ") {
				sev = finding.Critical
			}
			detail := v
			if cat == "file" {
				detail = "" // a content hash means nothing to a human
			}
			fs = append(fs, finding.Finding{
				ID: "ioc." + cat, Severity: sev,
				Title:  meta.what + " " + verb + " since baseline: " + k,
				Detail: detail,
				Fix:    iocFix,
			})
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Title < fs[j].Title })
	return fs
}

// Collect snapshots the host under root ("/" in production, a temp dir in tests).
func Collect(root string) Snapshot {
	s := Snapshot{"user": {}, "ssh-key": {}, "sudo-member": {}, "file": {}, "suid": {}, "port": {}}

	for user, home := range collectUsers(root, s["user"]) {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			b, _ := os.ReadFile(filepath.Join(root, home, ".ssh", name))
			for line := range strings.SplitSeq(string(b), "\n") {
				if fp := keyFingerprint(line); fp != "" {
					s["ssh-key"][user+" "+fp] = filepath.Join(home, ".ssh", name)
				}
			}
		}
	}
	collectSudoMembers(root, s["sudo-member"])

	for _, g := range watchedGlobs {
		matches, _ := filepath.Glob(filepath.Join(root, g))
		for _, p := range matches {
			hashInto(root, p, s["file"])
		}
	}
	// Enabling a unit adds a symlink under *.wants, so symlinks are recorded by target.
	filepath.WalkDir(filepath.Join(root, "etc/systemd/system"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			s["file"][rel(root, p)] = "-> " + target
		} else if d.Type().IsRegular() {
			hashInto(root, p, s["file"])
		}
		return nil
	})

	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && suidSkip[rel(root, p)] {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil && info.Mode()&fs.ModeSetuid != 0 {
				s["suid"][rel(root, p)] = ""
			}
		}
		return nil
	})

	for _, sock := range listening(root) {
		s["port"]["tcp "+sock.addr] = ""
	}
	return s
}

type socket struct{ addr, inode string }

// listening returns TCP sockets in LISTEN state. The inode links a socket to its process (see ports.go).
// ponytail: TCP only; add UDP when a check needs it.
func listening(root string) []socket {
	var socks []socket
	for _, proto := range []string{"tcp", "tcp6"} {
		b, _ := os.ReadFile(filepath.Join(root, "proc/net", proto))
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			s := socket{addr: procAddr(f[1])}
			if len(f) > 9 {
				s.inode = f[9]
			}
			if s.addr != "" {
				socks = append(socks, s)
			}
		}
	}
	return socks
}

// Live finds indicators that are suspicious on their own, without a baseline.
func Live(root string) []finding.Finding {
	var fs []finding.Finding

	if b, _ := os.ReadFile(filepath.Join(root, "etc/ld.so.preload")); strings.TrimSpace(string(b)) != "" {
		fs = append(fs, finding.Finding{
			ID: "ioc.ld-preload", Severity: finding.High,
			Title:  "/etc/ld.so.preload is not empty",
			Detail: "Every process loads these libraries — a classic rootkit technique. Legit uses are rare.",
			Fix:    "cat /etc/ld.so.preload  # if you didn't add it, assume compromise",
		})
	}

	pids := map[string][]string{} // exe -> pids
	entries, _ := os.ReadDir(filepath.Join(root, "proc"))
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join(root, "proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		pids[exe] = append(pids[exe], e.Name())
	}
	for exe, ps := range pids {
		inTmp := strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/dev/shm/") || strings.HasPrefix(exe, "/var/tmp/")
		deleted := strings.HasSuffix(exe, " (deleted)")
		if !inTmp && !deleted {
			continue
		}
		f := finding.Finding{
			ID: "ioc.suspicious-process", Severity: finding.High,
			Title:  "Process running from a temp dir: " + exe,
			Detail: "PIDs " + strings.Join(ps, ", ") + ". Miners and backdoors live in /tmp and /dev/shm.",
			Fix:    "cat /proc/" + ps[0] + "/cmdline | tr '\\0' ' '; ls -l /proc/" + ps[0] + "/cwd",
		}
		if !inTmp {
			f.Severity = finding.Medium
			f.Title = "Process running from a deleted binary: " + exe
			f.Detail = "PIDs " + strings.Join(ps, ", ") + ". Normal right after a package upgrade (restart the service); otherwise malware hiding its file."
		}
		fs = append(fs, f)
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Title < fs[j].Title })
	return fs
}

func collectUsers(root string, users map[string]string) (homes map[string]string) {
	homes = map[string]string{}
	b, _ := os.ReadFile(filepath.Join(root, "etc/passwd"))
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		homes[f[0]] = f[5] // keys of nologin users still allow tunnels, so collect all homes
		if f[2] == "0" || !strings.HasSuffix(f[6], "nologin") && !strings.HasSuffix(f[6], "false") {
			users[f[0]] = "uid=" + f[2] + " shell=" + f[6]
		}
	}
	return homes
}

func collectSudoMembers(root string, m map[string]string) {
	b, _ := os.ReadFile(filepath.Join(root, "etc/group"))
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Split(line, ":")
		// docker group can mount / into a container, so it is root too.
		if len(f) < 4 || f[0] != "sudo" && f[0] != "wheel" && f[0] != "admin" && f[0] != "docker" || f[3] == "" {
			continue
		}
		for u := range strings.SplitSeq(f[3], ",") {
			m[f[0]+":"+u] = ""
		}
	}
}

// keyFingerprint matches `ssh-keygen -lf` (SHA256 of the key blob); options and comments are skipped.
func keyFingerprint(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if !strings.HasPrefix(f[i], "ssh-") && !strings.HasPrefix(f[i], "ecdsa-") && !strings.HasPrefix(f[i], "sk-") {
			continue
		}
		if blob, err := base64.StdEncoding.DecodeString(f[i+1]); err == nil {
			sum := sha256.Sum256(blob)
			return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		}
	}
	sum := sha256.Sum256([]byte(line)) // unparseable line still counts as a key entry
	return "line:" + hex.EncodeToString(sum[:8])
}

// procAddr decodes /proc/net/tcp "0100007F:0016" (little-endian 32-bit words) into "127.0.0.1:22".
func procAddr(s string) string {
	ipHex, portHex, _ := strings.Cut(s, ":")
	raw, err := hex.DecodeString(ipHex)
	port, perr := strconv.ParseUint(portHex, 16, 16)
	if err != nil || perr != nil || len(raw) != 4 && len(raw) != 16 {
		return ""
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return net.JoinHostPort(net.IP(raw).String(), strconv.FormatUint(port, 10))
}

func hashInto(root, p string, m map[string]string) {
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	sum := sha256.Sum256(b)
	m[rel(root, p)] = hex.EncodeToString(sum[:])
}

func rel(root, p string) string {
	r, _ := filepath.Rel(root, p)
	return filepath.Clean("/" + r)
}
