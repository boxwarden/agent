package check

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestFiles(t *testing.T) {
	defer func(u int) { rootUID = u }(rootUID)
	rootUID = os.Getuid()
	root := t.TempDir()
	write(t, root, "etc/passwd", "")
	write(t, root, "etc/shadow", "")
	write(t, root, "etc/sudoers", "")
	os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	os.Symlink("usr/bin", filepath.Join(root, "bin"))
	os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755)
	os.Chmod(filepath.Join(root, "etc/passwd"), 0o666)
	os.Chmod(filepath.Join(root, "etc/shadow"), 0o644)
	os.Chmod(filepath.Join(root, "etc/sudoers"), 0o440)
	os.Chmod(filepath.Join(root, "etc/cron.d"), 0o1777) // sticky doesn't stop a new root cron job
	os.Chmod(filepath.Join(root, "usr/bin"), 0o755)

	var got []string
	for _, f := range files(root) {
		got = append(got, f.ID+" "+f.Title)
	}
	sort.Strings(got)
	want := []string{
		"files.shadow-readable /etc/shadow is readable by every user",
		"files.world-writable /etc/cron.d is writable by every user",
		"files.world-writable /etc/passwd is writable by every user",
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("got %q", got)
	}
}
