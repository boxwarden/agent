package check

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func TestAuthLogins(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	log := "2026-01-02T11:50:00.123456+00:00 web sshd[811]: Accepted publickey for root from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:abc/+def\n" +
		"2026-01-02T11:00:00+00:00 web sshd[700]: Accepted password for root from 203.0.113.7 port 1 ssh2\n" + // too old
		"Jan  2 11:58:00 web sshd-session[900]: Accepted password for deploy from 2001:db8::5 port 2222 ssh2\n" +
		"Jan  2 11:59:00 web sshd[901]: Failed password for root from 198.51.100.1 port 3 ssh2\n" +
		"Dec 31 23:59:00 web sshd[1]: Accepted password for old from 192.0.2.1 port 4 ssh2\n" // last year, not in the future
	got := fmt.Sprint(authLogins(log, now))
	want := "[{1767354600 root 203.0.113.7 publickey SHA256:abc/+def} {1767355080 deploy 2001:db8::5 password }]"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestWtmpLogins(t *testing.T) {
	now := time.Unix(1767355200, 0)
	rec := func(typ uint16, user string, at int64, addr []byte) []byte {
		r := make([]byte, utmpSize)
		binary.LittleEndian.PutUint16(r, typ)
		copy(r[44:], user)
		binary.LittleEndian.PutUint32(r[utmpTime:], uint32(at))
		copy(r[utmpAddr:], addr)
		return r
	}
	var b []byte
	b = append(b, rec(userProcess, "alice", now.Unix()-60, []byte{203, 0, 113, 7})...)
	b = append(b, rec(userProcess, "root", now.Unix()-30, nil)...)                      // console
	b = append(b, rec(8, "alice", now.Unix()-20, []byte{203, 0, 113, 7})...)            // DEAD_PROCESS: logout
	b = append(b, rec(userProcess, "bob", now.Unix()-3600, []byte{198, 51, 100, 1})...) // too old
	got := fmt.Sprint(wtmpLogins(b, now))
	if want := "[{1767355140 alice 203.0.113.7  }]"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
