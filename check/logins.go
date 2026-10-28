package check

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/boxwarden/agent/finding"
)

// loginWindow is how far back each sample looks. Samples go out every minute, so a login is sent
// several times; the cloud keeps it once, and a failed push or two loses nothing.
const loginWindow = 15 * time.Minute

var acceptedRe = regexp.MustCompile(`sshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port \d+(?: ssh2)?(?:: \S+ (SHA256:\S+))?`)

// recentLogins reads the SSH log of Debian/Ubuntu (auth.log) or RHEL (secure). Without rsyslog
// (Debian 12 and later by default) it falls back to wtmp, which records only sessions with a
// terminal: `ssh host command` isn't there. ponytail: journald's binary files and Debian 13's
// wtmpdb (SQLite) aren't read; a host with neither log sends no logins.
func recentLogins(root string, now time.Time) []finding.Login {
	for _, p := range []string{"var/log/auth.log", "var/log/secure"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return authLogins(string(readTail(root, p, 1<<20)), now)
		}
	}
	return wtmpLogins(readTail(root, "var/log/wtmp", int64(utmpSize)*2048), now)
}

func authLogins(log string, now time.Time) []finding.Login {
	var out []finding.Login
	for line := range strings.SplitSeq(log, "\n") {
		m := acceptedRe.FindStringSubmatch(line)
		if m == nil || net.ParseIP(m[3]) == nil {
			continue
		}
		if at, ok := syslogTime(line, now); ok && inWindow(at, now) {
			out = append(out, finding.Login{At: at.Unix(), User: m[2], From: m[3], Method: m[1], Key: m[4]})
		}
	}
	return out
}

// syslogTime reads the timestamp a log line starts with: RFC 3339 (rsyslog on Ubuntu 24.04 and
// later) or the classic "Oct 28 12:00:01", which has no year and is in local time.
func syslogTime(line string, now time.Time) (time.Time, bool) {
	first, _, _ := strings.Cut(line, " ")
	if t, err := time.Parse(time.RFC3339Nano, first); err == nil {
		return t, true
	}
	if len(line) < 15 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], now.Location())
	if err != nil {
		return time.Time{}, false
	}
	t = t.AddDate(now.Year(), 0, 0)
	if t.After(now.Add(24 * time.Hour)) { // December's lines read in January
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

func inWindow(at, now time.Time) bool {
	return !at.Before(now.Add(-loginWindow)) && !at.After(now.Add(time.Minute))
}

const userProcess = 7

// struct utmp, little-endian on both released architectures. amd64 glibc keeps 32-bit time fields
// for compatibility with 32-bit programs (384 bytes); arm64 has 64-bit ones (400 bytes).
var utmpSize, utmpTime, utmpAddr = 384, 340, 348

func init() {
	if runtime.GOARCH == "arm64" {
		utmpSize, utmpTime, utmpAddr = 400, 344, 360
	}
}

func wtmpLogins(b []byte, now time.Time) []finding.Login {
	var out []finding.Login
	for off := 0; off+utmpSize <= len(b); off += utmpSize {
		r := b[off : off+utmpSize]
		if binary.LittleEndian.Uint16(r[0:]) != userProcess {
			continue
		}
		addr := r[utmpAddr : utmpAddr+16]
		var ip net.IP
		switch {
		case allZero(addr):
			continue // a console login: no network
		case allZero(addr[4:]):
			ip = net.IP(addr[:4])
		default:
			ip = net.IP(addr)
		}
		at := time.Unix(int64(int32(binary.LittleEndian.Uint32(r[utmpTime:]))), 0) // low half of an int64 on arm64: good until 2038
		if inWindow(at, now) {
			out = append(out, finding.Login{At: at.Unix(), User: cString(r[44:76]), From: ip.String()})
		}
	}
	return out
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func cString(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\x00")
	return s
}

// readTail returns up to the last n bytes of a regular file; a wtmp tail starts on a record boundary.
func readTail(root, path string, n int64) []byte {
	f := openRegular(func(flags int) (*os.File, error) { return os.OpenFile(filepath.Join(root, path), flags, 0) })
	if f == nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	start := max(0, info.Size()-n)
	if strings.HasSuffix(path, "wtmp") {
		start = start / int64(utmpSize) * int64(utmpSize)
	}
	b, _ := io.ReadAll(io.NewSectionReader(f, start, info.Size()-start))
	return b
}
