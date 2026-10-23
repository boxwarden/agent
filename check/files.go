package check

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/boxwarden/agent/finding"
)

// Files whose permissions alone decide who is root: if any user can write one, any user can become root.
var rootOnly = []string{
	"etc/passwd", "etc/shadow", "etc/group", "etc/gshadow",
	"etc/sudoers", "etc/sudoers.d", "etc/crontab", "etc/cron.d", "etc/cron.hourly", "etc/cron.daily",
	"etc/systemd/system", "etc/ld.so.preload", "etc/ld.so.conf.d", "etc/profile", "etc/profile.d", "etc/pam.d",
	"etc/ssh", "etc/ssh/sshd_config", "etc/ssh/sshd_config.d", "root", "root/.ssh", "root/.ssh/authorized_keys",
	"usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin", "usr/lib/systemd/system", "lib/systemd/system",
}

// Files: system files and directories that users can write or read when they shouldn't.
func Files() ([]finding.Finding, error) {
	return files("/"), nil
}

func files(root string) []finding.Finding {
	var out []finding.Finding
	for _, p := range rootOnly {
		info, err := os.Lstat(filepath.Join(root, p))
		if err != nil || info.Mode()&fs.ModeSymlink != 0 { // /bin -> usr/bin: the target is checked itself
			continue
		}
		path := "/" + p
		mode := info.Mode().Perm()
		if mode&0o002 != 0 { // sticky doesn't help: a new file in cron.d or sudoers.d is enough
			out = append(out, finding.Finding{
				ID: "files.world-writable", Severity: finding.Critical,
				Title:  path + " is writable by every user",
				Detail: "Mode " + mode.String() + ". Any account, including a hacked web app, can use it to become root.",
				Fix:    "sudo chmod o-w " + path + "   # and find out who changed it",
			})
		} else if uid := ownerUID(info); uid >= 0 && uid != rootUID {
			out = append(out, finding.Finding{
				ID: "files.owner", Severity: finding.High,
				Title:  path + " is owned by UID " + strconv.Itoa(uid) + ", not root",
				Detail: "That account can change it and become root.",
				Fix:    "sudo chown root " + path,
			})
		}
	}
	// Password hashes: readable by anyone means offline cracking of every password.
	for _, p := range []string{"etc/shadow", "etc/gshadow"} {
		if info, err := os.Lstat(filepath.Join(root, p)); err == nil && info.Mode().Perm()&0o004 != 0 {
			out = append(out, finding.Finding{
				ID: "files.shadow-readable", Severity: finding.Critical,
				Title:  "/" + p + " is readable by every user",
				Detail: "It holds the password hashes; any account can copy and crack them offline.",
				Fix:    "sudo chmod 640 /" + p + " && sudo chown root:shadow /" + p + "   # RHEL: chmod 000",
			})
		}
	}
	return out
}
