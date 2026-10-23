package check

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuth(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(s), 0o600)
	}
	write("etc/passwd", `root:x:0:0:root:/root:/bin/bash
toor:x:0:0::/root:/bin/sh
redis:x:110:110::/var/lib/redis:/usr/sbin/nologin
git:x:111:111::/home/git:/bin/sh
anna:x:1000:1000::/home/anna:/bin/bash
guest:x:1001:1001::/home/guest:/bin/bash
svc:x:1002:1002::/home/svc:/usr/sbin/nologin
`)
	write("etc/shadow", "root:!:1::::::\ntoor:$6$x:1::::::\nanna:$6$y:1::::::\nguest::1::::::\nredis:*:1::::::\n")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x\n"
	write("var/lib/redis/.ssh/authorized_keys", key)
	write("home/git/.ssh/authorized_keys", `command="gitea serv key-1",no-pty `+key)
	write("home/anna/.ssh/authorized_keys", key)
	write("home/svc/.ssh/authorized_keys", key)

	got := map[string]int{}
	for _, f := range auth(root) {
		got[f.ID+" "+f.Title[:min(len(f.Title), 40)]]++
		got[f.ID]++
	}
	want := map[string]int{"auth.uid0": 1, "auth.empty-password": 1, "auth.service-account-key": 2}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s: got %d, want %d (%v)", id, got[id], n, got)
		}
	}
	if !rootLocked(root) {
		t.Error("root:! is locked")
	}
}
