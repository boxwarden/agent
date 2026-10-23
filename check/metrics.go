package check

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boxwarden/agent/finding"
)

// Filesystems that hold data. tmpfs, overlay (containers), squashfs (snaps) and network mounts are
// left out: they either can't fill up the server or could hang statfs.
var diskFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "bcachefs": true, "vfat": true}

const clkTck = 100 // USER_HZ: jiffies per second on every mainstream Linux build

// Metrics samples the host's resources. It takes about a second (process CPU is measured over it).
func Metrics() finding.Metrics {
	return metrics("/", time.Second)
}

func metrics(root string, sample time.Duration) finding.Metrics {
	var m finding.Metrics
	before := procTimes(root)
	start := time.Now()

	for line := range strings.SplitSeq(readFile(root, "proc/stat"), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) > 8 && f[0] == "cpu":
			var t [8]uint64 // user nice system idle iowait irq softirq steal; guest is already in user
			for i := range t {
				t[i], _ = strconv.ParseUint(f[i+1], 10, 64)
				m.CPU.Total += t[i]
			}
			m.CPU.Idle, m.CPU.IOWait, m.CPU.Steal = t[3], t[4], t[7]
		case len(f) > 1 && strings.HasPrefix(f[0], "cpu"):
			m.NumCPU++
		case len(f) == 2 && f[0] == "btime":
			m.BootTime, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	if f := strings.Fields(readFile(root, "proc/loadavg")); len(f) >= 3 {
		for i := range 3 {
			m.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	mem := map[string]uint64{}
	for line := range strings.SplitSeq(readFile(root, "proc/meminfo"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			mem[k] = n * 1024
		}
	}
	m.MemTotal, m.MemAvailable, m.SwapTotal, m.SwapFree = mem["MemTotal"], mem["MemAvailable"], mem["SwapTotal"], mem["SwapFree"]
	for line := range strings.SplitSeq(readFile(root, "proc/vmstat"), "\n") {
		if n, ok := strings.CutPrefix(line, "oom_kill "); ok {
			m.OOMKills, _ = strconv.ParseUint(n, 10, 64)
		}
	}
	m.NetRx, m.NetTx = netBytes(root)
	m.Disks = disks(root)

	if wait := sample - time.Since(start); wait > 0 {
		time.Sleep(wait)
	}
	m.Top = topProcs(root, before, procTimes(root), time.Since(start))
	return m
}

// netBytes sums traffic on physical interfaces (those with a device behind them), so traffic that
// goes through docker0, veth pairs or a VPN isn't counted twice.
func netBytes(root string) (rx, tx uint64) {
	var allRx, allTx uint64
	physical := false
	for line := range strings.SplitSeq(readFile(root, "proc/net/dev"), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		f := strings.Fields(rest)
		name = strings.TrimSpace(name)
		if !ok || len(f) < 9 || name == "lo" {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		t, _ := strconv.ParseUint(f[8], 10, 64)
		allRx, allTx = allRx+r, allTx+t
		if _, err := os.Stat(filepath.Join(root, "sys/class/net", name, "device")); err == nil {
			physical = true
			rx, tx = rx+r, tx+t
		}
	}
	if !physical { // some VMs and containers expose no device links
		return allRx, allTx
	}
	return rx, tx
}

func disks(root string) []finding.Disk {
	var out []finding.Disk
	seen := map[string]bool{}
	for line := range strings.SplitSeq(readFile(root, "proc/self/mounts"), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !diskFS[f[2]] || seen[f[0]] {
			continue // bind mounts repeat the device: count each filesystem once
		}
		seen[f[0]] = true
		mount := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(f[1])
		d, ok := statfs(filepath.Join(root, mount))
		if !ok || d.Size == 0 {
			continue
		}
		d.Mount, d.FS = finding.Clean(mount, 200), f[2]
		out = append(out, d)
		if len(out) == 32 {
			break
		}
	}
	return out
}

type procTime struct {
	name  string
	ticks uint64
}

// procTimes reads utime+stime of every process.
func procTimes(root string) map[int]procTime {
	out := map[int]procTime{}
	entries, _ := os.ReadDir(filepath.Join(root, "proc"))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		s := readFile(root, "proc/"+e.Name()+"/stat")
		// "1234 (name with) spaces) S ppid ..." : the name ends at the last ')'
		open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || end < open {
			continue
		}
		f := strings.Fields(s[end+1:])
		if len(f) < 13 {
			continue
		}
		u, _ := strconv.ParseUint(f[11], 10, 64)
		st, _ := strconv.ParseUint(f[12], 10, 64)
		out[pid] = procTime{s[open+1 : end], u + st}
	}
	return out
}

func topProcs(root string, before, after map[int]procTime, elapsed time.Duration) []finding.Proc {
	var ps []finding.Proc
	for pid, a := range after {
		b, ok := before[pid]
		if !ok || a.ticks <= b.ticks {
			continue
		}
		cpu := float64(a.ticks-b.ticks) / clkTck / elapsed.Seconds() * 100
		ps = append(ps, finding.Proc{PID: pid, Name: finding.Clean(a.name, 64), CPU: float64(int(cpu*10)) / 10})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].CPU > ps[j].CPU })
	ps = ps[:min(5, len(ps))]
	page := uint64(os.Getpagesize())
	for i := range ps {
		if f := strings.Fields(readFile(root, "proc/"+strconv.Itoa(ps[i].PID)+"/statm")); len(f) > 1 {
			n, _ := strconv.ParseUint(f[1], 10, 64)
			ps[i].RSS = n * page
		}
	}
	return ps
}
