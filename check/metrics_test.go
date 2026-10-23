package check

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetrics(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/stat", "cpu  100 0 50 800 40 0 0 10 5 0\ncpu0 50 0 25 400 20 0 0 5 0 0\ncpu1 50 0 25 400 20 0 0 5 0 0\nbtime 1790000000\n")
	write(t, root, "proc/loadavg", "1.50 0.75 0.25 2/300 999\n")
	write(t, root, "proc/meminfo", "MemTotal:        2048000 kB\nMemFree:          100000 kB\nMemAvailable:     512000 kB\nSwapTotal:        1024000 kB\nSwapFree:         1024000 kB\n")
	write(t, root, "proc/vmstat", "nr_free_pages 1\noom_kill 3\n")
	write(t, root, "proc/net/dev", "Inter-|   Receive\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n"+
		"    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n"+
		"  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0\n"+
		"docker0: 500 1 0 0 0 0 0 0 700 1 0 0 0 0 0 0\n")
	os.MkdirAll(filepath.Join(root, "sys/class/net/eth0/device"), 0o755)
	write(t, root, "proc/42/stat", "42 (evil (miner)) R 1 42 42 0 -1 4194560 0 0 0 0 100 50 0 0 20 0 1 0 1 0 0\n")
	write(t, root, "proc/42/statm", "1000 250 0 0 0 0 0\n")

	m := metrics(root, 0)
	if m.NumCPU != 2 || m.CPU.Total != 1000 || m.CPU.Idle != 800 || m.CPU.IOWait != 40 || m.CPU.Steal != 10 || m.BootTime != 1790000000 {
		t.Errorf("cpu: %+v n=%d boot=%d", m.CPU, m.NumCPU, m.BootTime)
	}
	if m.Load != [3]float64{1.5, 0.75, 0.25} || m.MemTotal != 2048000*1024 || m.MemAvailable != 512000*1024 || m.OOMKills != 3 {
		t.Errorf("load/mem: %+v", m)
	}
	if m.NetRx != 1000 || m.NetTx != 2000 {
		t.Errorf("net counts only eth0 (physical): rx=%d tx=%d", m.NetRx, m.NetTx)
	}

	before := map[int]procTime{42: {"evil (miner)", 50}}
	top := topProcs(root, before, procTimes(root), time.Second)
	if len(top) != 1 || top[0].Name != "evil (miner)" || top[0].CPU != 100 || top[0].RSS != 250*uint64(os.Getpagesize()) {
		t.Errorf("top: %+v", top)
	}
}

func TestOOMVictims(t *testing.T) {
	log := "3,812,99000000,-;Memory cgroup out of memory: Killed process 575672 (boxwarden) total-vm:1767192kB, anon-rss:522892kB, file-rss:6272kB, shmem-rss:0kB, UID:0 pgtables:1144kB oom_score_adj:0\n" +
		" SUBSYSTEM=memory\n" +
		"3,900,120500000,-;Out of memory: Killed process 42 (my app) total-vm:10kB, anon-rss:2048kB, file-rss:0kB\n"
	v := oomVictims(log, 1000)
	if len(v) != 2 || v[0].Name != "boxwarden" || v[0].PID != 575672 || v[0].RSS != 522892*1024 || v[0].At != 1099 ||
		v[1].Name != "my app" || v[1].At != 1120 {
		t.Errorf("victims: %+v", v)
	}
}
