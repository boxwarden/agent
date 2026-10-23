package check

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/boxwarden/agent/finding"
)

var now = time.Now // swapped in tests

// End of security updates, including free LTS (Debian LTS); paid extensions are checked separately.
// Unknown versions are never flagged, so a release newer than this table stays quiet.
var eolDates = map[string]string{
	"ubuntu 14.04": "2019-04-30", "ubuntu 16.04": "2021-04-30", "ubuntu 18.04": "2023-05-31", "ubuntu 20.04": "2025-05-31",
	"ubuntu 22.04": "2027-06-01", "ubuntu 24.04": "2029-05-31",
	"ubuntu 22.10": "2023-07-20", "ubuntu 23.04": "2024-01-25", "ubuntu 23.10": "2024-07-11", "ubuntu 24.10": "2025-07-10",
	"ubuntu 25.04": "2026-01-15", "ubuntu 25.10": "2026-07-09",
	"debian 8": "2020-06-30", "debian 9": "2022-06-30", "debian 10": "2024-06-30", "debian 11": "2026-08-31", "debian 12": "2028-06-30",
	"centos 7": "2024-06-30", "centos 8": "2021-12-31",
	"almalinux 8": "2029-03-01", "rocky 8": "2029-05-31", "almalinux 9": "2032-05-31", "rocky 9": "2032-05-31",
}

// Updates finds a host that no longer gets or no longer applies security fixes.
func Updates() ([]finding.Finding, error) {
	return updates("/"), nil
}

func updates(root string) []finding.Finding {
	var fs []finding.Finding
	osr := stanza(readFile(root, "etc/os-release"), "=")
	id, ver := strings.Trim(osr["ID"], `"`), strings.Trim(osr["VERSION_ID"], `"`)
	if id != "ubuntu" {
		ver, _, _ = strings.Cut(ver, ".") // Debian 12.5, Rocky 9.4: the major version decides
	}
	name := strings.Trim(osr["PRETTY_NAME"], `"`)
	if name == "" {
		name = id + " " + ver
	}
	if eol, ok := eolDates[id+" "+ver]; ok && now().Format(time.DateOnly) > eol && !ubuntuPro(root) {
		fs = append(fs, finding.Finding{
			ID: "updates.os-eol", Severity: finding.High,
			Title:  name + " no longer gets security updates (ended " + eol + ")",
			Detail: "New vulnerabilities in this release are never fixed, so the vulnerability scan can look clean while the server is not.",
			Fix:    eolFix(id),
		})
	}
	if f, ok := rebootRequired(root); ok {
		fs = append(fs, f)
	}
	if f, ok := autoUpdatesOff(root, id); ok {
		fs = append(fs, f)
	}
	return fs
}

func eolFix(id string) string {
	switch id {
	case "ubuntu":
		return "Upgrade to a supported LTS: sudo do-release-upgrade (back up first), or rebuild on a fresh LTS image. Ubuntu Pro (free for 5 machines) extends updates: sudo pro attach"
	case "debian":
		return "Upgrade to the current stable release (https://www.debian.org/releases/), or rebuild on a fresh image"
	default:
		return "Rebuild on a supported release (AlmaLinux/Rocky 9, Debian 13 or Ubuntu 24.04)"
	}
}

// ubuntuPro is true when ESM is attached: it keeps fixing an otherwise EOL release.
func ubuntuPro(root string) bool {
	var st struct{ Attached bool }
	return json.Unmarshal([]byte(readFile(root, "var/lib/ubuntu-advantage/status.json")), &st) == nil && st.Attached
}

// rebootRequired: fixes to the kernel (or libc) are installed but only apply after a reboot.
func rebootRequired(root string) (finding.Finding, bool) {
	f := finding.Finding{
		ID: "updates.reboot-required", Severity: finding.Medium,
		Title:  "Security updates are installed but need a reboot to take effect",
		Detail: "Until then the server runs the old, vulnerable code.",
		Fix:    "sudo reboot   # at a quiet time",
	}
	running := strings.TrimSpace(readFile(root, "proc/sys/kernel/osrelease"))
	if livepatched(root) {
		return f, false
	}
	// Debian/Ubuntu: packages ask for a reboot. Give unattended upgrades a few days before nagging.
	if info, err := os.Stat(filepath.Join(root, "run/reboot-required")); err == nil {
		if now().Sub(info.ModTime()) < 3*24*time.Hour {
			return f, false
		}
		if pkgs := strings.Fields(readFile(root, "run/reboot-required.pkgs")); len(pkgs) > 0 {
			slices.Sort(pkgs)
			f.Detail = "Waiting for a reboot since " + info.ModTime().Format(time.DateOnly) + ": " + strings.Join(slices.Compact(pkgs), ", ") + ". " + f.Detail
		}
		return f, true
	}
	// Elsewhere: a kernel newer than the running one is installed.
	if running == "" {
		return f, false
	}
	cur, err := os.Stat(filepath.Join(root, "boot", "vmlinuz-"+running))
	if err != nil {
		return f, false
	}
	kernels, _ := filepath.Glob(filepath.Join(root, "boot", "vmlinuz-*"))
	for _, k := range kernels {
		if info, err := os.Stat(k); err == nil && !strings.Contains(k, "rescue") && info.ModTime().After(cur.ModTime().Add(24*time.Hour)) {
			f.Detail = "Running kernel " + running + ", installed " + strings.TrimPrefix(filepath.Base(k), "vmlinuz-") + ". " + f.Detail
			return f, true
		}
	}
	return f, false
}

func livepatched(root string) bool {
	m, _ := filepath.Glob(filepath.Join(root, "sys/kernel/livepatch/*/enabled"))
	for _, p := range m {
		if strings.TrimSpace(readFile(root, rel(root, p))) == "1" {
			return true
		}
	}
	return false
}

// autoUpdatesOff: nothing installs security fixes automatically, and nobody has by hand in two weeks.
// The second condition keeps quiet people who patch with Ansible or by hand.
func autoUpdatesOff(root, id string) (finding.Finding, bool) {
	f := finding.Finding{
		ID: "updates.auto-off", Severity: finding.Medium,
		Title:  "Security updates are not installed automatically",
		Detail: "Most break-ins use bugs that were fixed weeks earlier.",
	}
	var last time.Time
	switch id {
	case "debian", "ubuntu":
		if dpkgInstalled(root, "unattended-upgrades") && aptPeriodic(root) {
			return f, false
		}
		last = lastDpkgUpgrade(root)
		f.Fix = "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
	case "rhel", "centos", "almalinux", "rocky", "fedora", "amzn", "ol":
		if m, _ := filepath.Glob(filepath.Join(root, "etc/systemd/system/timers.target.wants/dnf-automatic*.timer")); len(m) > 0 {
			return f, false
		}
		if info, err := os.Stat(filepath.Join(root, "var/lib/dnf/history.sqlite")); err == nil {
			last = info.ModTime()
		}
		f.Fix = "sudo dnf install -y dnf-automatic && sudo sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf && sudo systemctl enable --now dnf-automatic.timer"
	default:
		return f, false
	}
	if now().Sub(last) < 14*24*time.Hour {
		return f, false
	}
	if !last.IsZero() {
		f.Detail = "Last package upgrade: " + last.Format(time.DateOnly) + ". " + f.Detail
	}
	return f, true
}

func dpkgInstalled(root, name string) bool {
	for s := range strings.SplitSeq(readFile(root, "var/lib/dpkg/status"), "\n\n") {
		if f := stanza(s, ": "); f["Package"] == name {
			return f["Status"] == "install ok installed"
		}
	}
	return false
}

// aptPeriodic reads APT::Periodic::Unattended-Upgrade from apt.conf.d; files apply in name order, last wins.
func aptPeriodic(root string) bool {
	on := false
	files, _ := filepath.Glob(filepath.Join(root, "etc/apt/apt.conf.d/*"))
	slices.Sort(files)
	for _, p := range files {
		for line := range strings.SplitSeq(readFile(root, rel(root, p)), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "//") || !strings.HasPrefix(line, `APT::Periodic::Unattended-Upgrade `) {
				continue
			}
			v := strings.Trim(strings.TrimPrefix(line, "APT::Periodic::Unattended-Upgrade "), `"; `)
			on = v != "0" && v != "" && v != "false"
		}
	}
	return on
}

// lastDpkgUpgrade is the newest "upgrade" in dpkg.log and its first rotation.
func lastDpkgUpgrade(root string) time.Time {
	var last time.Time
	for _, p := range []string{"var/log/dpkg.log", "var/log/dpkg.log.1"} {
		for line := range strings.SplitSeq(readFile(root, p), "\n") {
			if f := strings.Fields(line); len(f) > 2 && f[2] == "upgrade" {
				if t, err := time.Parse(time.DateTime, f[0]+" "+f[1]); err == nil && t.After(last) {
					last = t
				}
			}
		}
	}
	return last
}
