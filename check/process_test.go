package check

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestProcessIndicators(t *testing.T) {
	root := t.TempDir()
	proc := func(pid, comm, cmdline, exe string, fds map[string]string) {
		d := filepath.Join(root, "proc", pid)
		os.MkdirAll(filepath.Join(d, "fd"), 0o755)
		os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
		os.WriteFile(filepath.Join(d, "cmdline"), []byte(cmdline), 0o644)
		if exe != "" {
			os.Symlink(exe, filepath.Join(d, "exe"))
		}
		for fd, target := range fds {
			os.Symlink(target, filepath.Join(d, "fd", fd))
		}
	}
	proc("10", "kworker/0:1", "", "", nil)                                                          // real kernel thread: no exe
	proc("11", "kworker/0:2", "[kworker/0:2]\x00", "/var/tmp/.k/kw", nil)                           // fake
	proc("12", "watchdog", "/usr/sbin/watchdog\x00", "/usr/sbin/watchdog", nil)                     // userspace watchdog daemon
	proc("13", "systemd-helper", "./h\x00-o\x00stratum+tcp://pool.example:3333\x00", "/opt/h", nil) // renamed miner
	proc("14", "xmrig", "xmrig\x00", "/root/.cache/xmrig", nil)
	proc("15", "bash", "bash\x00-i\x00", "/usr/bin/bash", map[string]string{"0": "socket:[777]", "1": "socket:[777]", "2": "socket:[777]"})
	proc("16", "bash", "-bash\x00", "/usr/bin/bash", map[string]string{"0": "/dev/pts/0"}) // an SSH session
	proc("17", "python3", "python3\x00app.py\x00", "/usr/bin/python3.12", map[string]string{"0": "socket:[888]"})
	// 777: ESTABLISHED 10.0.0.5:51234 -> 203.0.113.9:4444; 888: ESTABLISHED to 127.0.0.1 (a local supervisor)
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0500000A:C822 0971CBCB:115C 01 00000000:00000000 00:00000000 00000000     0        0 777 1\n" +
		"   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 888 1\n"
	for _, pid := range []string{"15", "17"} {
		os.MkdirAll(filepath.Join(root, "proc", pid, "net"), 0o755)
		os.WriteFile(filepath.Join(root, "proc", pid, "net", "tcp"), []byte(tcp), 0o644)
	}

	var got []string
	for _, f := range processIndicators(root) {
		got = append(got, f.ID+" "+f.Title)
	}
	sort.Strings(got)
	want := []string{
		"ioc.fake-kthread Process disguised as a kernel thread: kworker/0:2 (PID 11)",
		"ioc.miner Crypto miner running: systemd-helper (PID 13)",
		"ioc.miner Crypto miner running: xmrig (PID 14)",
		"ioc.reverse-shell Shell connected straight to the network: bash (PID 15) ↔ 203.203.113.9:4444",
	}
	if len(got) != len(want) {
		t.Fatalf("got\n%q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %q, want %q", got[i], want[i])
		}
	}
}
