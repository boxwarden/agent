package check

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/boxwarden/agent/finding"
)

// The units install.sh writes. They appear after the baseline is taken and change with every
// update, so they stay out of the baseline; instead their content must match what install.sh
// writes, or an attacker could hide a command in them.
var ownUnits = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range []string{"scan", "cve", "metrics"} {
		m["/etc/systemd/system/boxwarden-"+n+".service"] = true
		m["/etc/systemd/system/boxwarden-"+n+".timer"] = true
		m["/etc/systemd/system/timers.target.wants/boxwarden-"+n+".timer"] = true
	}
	return m
}()

var (
	ownExec = regexp.MustCompile(`^/usr/local/bin/boxwarden (scan|metrics)( --[a-z]+( [a-z,]+)?)*$`)
	// Keys install.sh writes; anything else (ExecStartPre, Environment, User...) is not ours.
	ownKeys = map[string]bool{
		"Description": true, "After": true, "Wants": true, "Type": true, "ExecStart": true,
		"ProtectSystem": true, "ProtectHome": true, "NoNewPrivileges": true, "TimeoutStartSec": true, "MemoryMax": true, "Nice": true,
		"OnBootSec": true, "OnUnitActiveSec": true, "RandomizedDelaySec": true, "OnCalendar": true, "Persistent": true,
		"AccuracySec": true, "WantedBy": true,
	}
)

// ownUnitFindings reports Boxwarden units that contain anything install.sh doesn't write.
func ownUnitFindings(root string) []finding.Finding {
	var fs []finding.Finding
	for path := range ownUnits {
		why := ""
		if dir, name := filepath.Split(path); strings.HasSuffix(dir, ".wants/") {
			if target, err := os.Readlink(filepath.Join(root, path)); err == nil && target != "/etc/systemd/system/"+name && target != "../"+name {
				why = "the timer link points to " + target
			}
		} else {
			why = unitProblem(readFile(root, path))
		}
		if why != "" {
			fs = append(fs, finding.Finding{
				ID: "ioc.agent-unit", Severity: finding.Critical,
				Title:  "Boxwarden's own unit was modified: " + path,
				Detail: "It runs as root on a timer, which makes it a good place to hide a command. Found: " + why + ".",
				Fix:    "cat " + path + "   # if you didn't edit it, assume compromise; to restore the unit: curl -fsSL https://github.com/boxwarden/agent/releases/latest/download/install.sh | sudo sh",
			})
		}
	}
	return fs
}

func unitProblem(unit string) string {
	for line := range strings.SplitSeq(unit, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		switch {
		case !ownKeys[k]:
			return k + "="
		case k == "ExecStart" && !ownExec.MatchString(v):
			return "ExecStart=" + v
		}
	}
	return ""
}
