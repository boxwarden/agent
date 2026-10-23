package check

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadFileRefusesTraps(t *testing.T) {
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "shadow"), []byte("secret"), 0o600)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/real"), []byte("ok"), 0o644)
	os.Symlink("real", filepath.Join(root, "etc/inside"))
	os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(root, "etc/escape"))
	if err := syscall.Mkfifo(filepath.Join(root, "etc/fifo"), 0o644); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]string{
		"etc/real":   "ok",
		"/etc/real":  "ok",
		"etc/inside": "", // a container's own symlinks aren't followed either
		"etc/escape": "", // a container's symlink must not read the host
		"etc/fifo":   "", // must return, not block
		"etc/nope":   "",
	} {
		if got := readFile(root, path); got != want {
			t.Errorf("readFile(%s) = %q, want %q", path, got, want)
		}
	}
}

// A user's symlink to a device must not get it opened (opening /dev/watchdog reboots the host).
func TestReadFileSkipsDevices(t *testing.T) {
	home := t.TempDir()
	os.Symlink("/dev/null", filepath.Join(home, "authorized_keys"))
	if got := readFile("/", filepath.Join(home, "authorized_keys")); got != "" {
		t.Errorf("read a device: %q", got)
	}
}
