// Package finding is the wire format shared by the agent and the Boxwarden cloud.
// It carries results only — never file contents or secrets (see ADR-0002).
package finding

import "encoding/json"

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
