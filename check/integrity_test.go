package check

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

func TestIntegrity(t *testing.T) {
	root := t.TempDir()
	sum := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
	write(t, root, "usr/bin/ps", "trojan")
	write(t, root, "usr/bin/top", "top")
	write(t, root, "usr/sbin/sshd", "diverted build")
	write(t, root, "usr/share/doc/procps/README", "edited by hand")
	write(t, root, "var/lib/dpkg/info/procps.md5sums",
		sum("ps")+"  usr/bin/ps\n"+sum("top")+"  usr/bin/top\n"+sum("x")+"  usr/share/doc/procps/README\n"+sum("x")+"  usr/bin/gone\n")
	write(t, root, "var/lib/dpkg/info/openssh-server.md5sums", sum("sshd")+"  usr/sbin/sshd\n")
	write(t, root, "var/lib/dpkg/info/loginctl-tool.md5sums", sum("x")+"  usr/bin/top\n") // not the "login" package
	write(t, root, "var/lib/dpkg/diversions", "/usr/sbin/sshd\n/usr/sbin/sshd.distrib\nhardened-sshd\n")

	fs := integrity(root)
	if len(fs) != 1 || fs[0].Title != "System binary differs from its package: /usr/bin/ps (procps)" {
		t.Errorf("got %+v", fs)
	}
}
