package check

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdates(t *testing.T) {
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }

	host := func(files map[string]string) string {
		root := t.TempDir()
		for p, s := range files {
			os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
			os.WriteFile(filepath.Join(root, p), []byte(s), 0o644)
		}
		return root
	}
	ids := func(root string) map[string]string {
		m := map[string]string{}
		for _, f := range updates(root) {
			m[f.ID] = f.Title + " | " + f.Detail
		}
		return m
	}
	auto := `Package: unattended-upgrades
Status: install ok installed
Version: 2.9
`
	autoOn := `APT::Periodic::Unattended-Upgrade "1";`

	// Ubuntu 20.04 with auto updates: EOL only.
	got := ids(host(map[string]string{
		"etc/os-release":                     "ID=ubuntu\nVERSION_ID=\"20.04\"\nPRETTY_NAME=\"Ubuntu 20.04.6 LTS\"\n",
		"var/lib/dpkg/status":                auto,
		"etc/apt/apt.conf.d/20auto-upgrades": autoOn,
		"etc/apt/apt.conf.d/10periodic":      `APT::Periodic::Unattended-Upgrade "0";`, // earlier file, overridden
		"proc/sys/kernel/osrelease":          "5.4.0-1\n",
	}))
	if len(got) != 1 || got["updates.os-eol"] == "" {
		t.Errorf("ubuntu 20.04: %v", got)
	}
	// ...unless Ubuntu Pro is attached.
	if got := ids(host(map[string]string{
		"etc/os-release":                       "ID=ubuntu\nVERSION_ID=\"20.04\"\n",
		"var/lib/ubuntu-advantage/status.json": `{"attached": true}`,
		"var/lib/dpkg/status":                  auto,
		"etc/apt/apt.conf.d/20auto-upgrades":   autoOn,
	})); len(got) != 0 {
		t.Errorf("ubuntu pro: %v", got)
	}

	// Debian 12, no unattended-upgrades, last upgrade a month ago: auto-off.
	got = ids(host(map[string]string{
		"etc/os-release":   "ID=debian\nVERSION_ID=\"12\"\n",
		"var/log/dpkg.log": "2026-09-01 10:00:00 upgrade openssl:amd64 3.0.1 3.0.2\n2026-09-01 10:00:01 status installed openssl:amd64 3.0.2\n",
	}))
	if len(got) != 1 || got["updates.auto-off"] == "" {
		t.Errorf("debian stale: %v", got)
	}
	// Same but upgraded by hand last week: quiet.
	if got := ids(host(map[string]string{
		"etc/os-release":   "ID=debian\nVERSION_ID=\"12\"\n",
		"var/log/dpkg.log": "2026-09-27 10:00:00 upgrade openssl:amd64 3.0.1 3.0.2\n",
	})); len(got) != 0 {
		t.Errorf("debian patched by hand: %v", got)
	}

	// Reboot pending for a week with a kernel package.
	root := host(map[string]string{
		"etc/os-release":            "ID=debian\nVERSION_ID=\"13\"\n",
		"var/lib/dpkg/status":       auto,
		"etc/apt/apt.conf.d/20auto": autoOn,
		"run/reboot-required":       "*** System restart required ***\n",
		"run/reboot-required.pkgs":  "linux-image-6.12.0-2-amd64\nlinux-base\nlinux-base\n",
	})
	week := now().Add(-7 * 24 * time.Hour)
	os.Chtimes(filepath.Join(root, "run/reboot-required"), week, week)
	got = ids(root)
	if len(got) != 1 || got["updates.reboot-required"] == "" {
		t.Errorf("reboot: %v", got)
	}
	// A fresh one is not nagged.
	os.Chtimes(filepath.Join(root, "run/reboot-required"), now(), now())
	if got := ids(root); len(got) != 0 {
		t.Errorf("fresh reboot-required: %v", got)
	}

	// RHEL-like: newer kernel installed, running old one.
	root = host(map[string]string{
		"etc/os-release": "ID=\"rocky\"\nVERSION_ID=\"9.4\"\n",
		"etc/systemd/system/timers.target.wants/dnf-automatic.timer": "",
		"proc/sys/kernel/osrelease":                                  "5.14.0-1.el9\n",
		"boot/vmlinuz-5.14.0-1.el9":                                  "",
		"boot/vmlinuz-5.14.0-9.el9":                                  "",
	})
	old := now().Add(-60 * 24 * time.Hour)
	os.Chtimes(filepath.Join(root, "boot/vmlinuz-5.14.0-1.el9"), old, old)
	if got := ids(root); len(got) != 1 || got["updates.reboot-required"] == "" {
		t.Errorf("rocky newer kernel: %v", got)
	}
}
