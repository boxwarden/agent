// Package finding is the wire format shared by the agent and the Heimdall cloud.
// It carries results only — never file contents or secrets (see ADR-0002).
package finding

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
}
