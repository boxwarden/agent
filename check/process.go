package check

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/boxwarden/agent/finding"
)

var (
	// Names miners ship under; matched on the binary and the process name.
	minerNames = regexp.MustCompile(`^(xmrig|xmr-stak|kdevtmpfsi|kinsing|minerd|cpuminer|cpuminer-opt|nbminer|lolminer|t-rex|srbminer-multi|phoenixminer|ethminer|gminer|teamredminer)$`)
	// Any miner, renamed or not, has to talk to a pool.
	minerArgs = regexp.MustCompile(`stratum2?\+(tcp|ssl|tls)://|--donate-level|--cpu-max-threads-hint|--randomx`)
	// Kernel threads have no binary; malware takes their names to blend into `ps`.
	kthreadNames = regexp.MustCompile(`^\[?(kworker|ksoftirqd|kthreadd|kswapd|migration/|rcu_|watchdog/|jbd2|kdevtmpfs|khugepaged|kcompactd|kblockd|kauditd|irq/)`)
	// What an attacker gets after `bash -i >& /dev/tcp/…`: a shell or interpreter with stdio on a TCP socket.
	shellNames = regexp.MustCompile(`^(sh|bash|dash|zsh|ash|ksh|busybox|python[0-9.]*|perl|php[0-9.]*|ruby|lua|node|nc|ncat|netcat|socat|telnet)$`)
)

// processIndicators looks at every process for things malware does and legit software doesn't.
func processIndicators(root string) []finding.Finding {
	var fs []finding.Finding
	entries, _ := os.ReadDir(filepath.Join(root, "proc"))
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		dir := "proc/" + pid
		comm := strings.TrimSpace(readFile(root, dir+"/comm"))
		cmdline := strings.ReplaceAll(readFile(root, dir+"/cmdline"), "\x00", " ")
		exe, exeErr := os.Readlink(filepath.Join(root, dir, "exe"))
		base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		inspect := "ls -l /proc/" + pid + "/exe /proc/" + pid + "/cwd; cat /proc/" + pid + "/cmdline | tr '\\0' ' '"

		switch {
		case minerNames.MatchString(strings.ToLower(comm)) || exeErr == nil && minerNames.MatchString(strings.ToLower(base)) || minerArgs.MatchString(cmdline):
			fs = append(fs, finding.Finding{
				ID: "ioc.miner", Severity: finding.Critical,
				Title:  "Crypto miner running: " + comm + " (PID " + pid + ")",
				Detail: "Miners are the most common payload after a break-in: whoever started it can run anything here. Binary: " + exe,
				Fix:    inspect + "   # then assume compromise: find how it got in, rebuild, rotate keys",
				Key:    "ioc.miner|" + exe,
			})
		case exeErr == nil && (kthreadNames.MatchString(comm) || strings.HasPrefix(cmdline, "[")):
			fs = append(fs, finding.Finding{
				ID: "ioc.fake-kthread", Severity: finding.Critical,
				Title:  "Process disguised as a kernel thread: " + comm + " (PID " + pid + ")",
				Detail: "Real kernel threads have no binary; this one runs " + exe + ". Malware hides in `ps` this way.",
				Fix:    inspect + "   # then assume compromise",
				Key:    "ioc.fake-kthread|" + exe,
			})
		case shellNames.MatchString(comm):
			if peer := stdioPeer(root, pid); peer != "" {
				fs = append(fs, finding.Finding{
					ID: "ioc.reverse-shell", Severity: finding.Critical,
					Title:  "Shell connected straight to the network: " + comm + " (PID " + pid + ") ↔ " + peer,
					Detail: "Its input/output is a TCP connection, not a terminal: the classic reverse shell an attacker opens after exploiting a service.",
					Fix:    inspect + "; sudo kill -9 " + pid + "   # then assume compromise",
					Key:    "ioc.reverse-shell|" + comm + "|" + peer,
				})
			}
		}
	}
	return fs
}

// stdioPeer returns the remote address when stdin, stdout or stderr is an established TCP connection.
func stdioPeer(root, pid string) string {
	inodes := map[string]bool{}
	for _, fd := range []string{"0", "1", "2"} {
		link, _ := os.Readlink(filepath.Join(root, "proc", pid, "fd", fd))
		if inode, ok := strings.CutPrefix(link, "socket:["); ok {
			inodes[strings.TrimSuffix(inode, "]")] = true
		}
	}
	if len(inodes) == 0 {
		return ""
	}
	// The process's own net namespace: a shell in a container has its sockets there.
	for _, proto := range []string{"tcp", "tcp6"} {
		for line := range strings.SplitSeq(readFile(root, "proc/"+pid+"/net/"+proto), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "01" || !inodes[f[9]] { // 01 = ESTABLISHED
				continue
			}
			remote := procAddr(f[2])
			if host, _, _ := net.SplitHostPort(remote); remote != "" && !net.ParseIP(host).IsLoopback() {
				return remote
			}
		}
	}
	return ""
}
