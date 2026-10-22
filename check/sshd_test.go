package check

import (
	"strings"
	"testing"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

func TestSSHDFindings(t *testing.T) {
	sev := func(cfg string, rootKeys bool) map[string]finding.Finding {
		m := map[string]finding.Finding{}
		for _, f := range sshdFindings(cfg, rootKeys) {
			m[f.ID] = f
		}
		return m
	}

	bad := sev("permitrootlogin yes\nPasswordAuthentication yes\npermitemptypasswords yes\n", false)
	if bad["ssh.root-password-login"].Severity != finding.Critical || bad["ssh.password-auth"].Severity != finding.High || bad["ssh.empty-passwords"].Severity != finding.Critical {
		t.Errorf("bad config: %v", bad)
	}
	if !strings.Contains(bad["ssh.root-password-login"].Detail, "root has no SSH keys") {
		t.Error("must warn that every login uses the password")
	}
	for id, f := range bad {
		if id != "ssh.empty-passwords" && !strings.HasPrefix(f.Fix, "FIRST add your key") {
			t.Errorf("%s: disabling passwords without a key locks the user out: %q", id, f.Fix)
		}
	}
	if strings.Contains(sev("permitrootlogin yes\npasswordauthentication yes\n", true)["ssh.root-password-login"].Detail, "no SSH keys") {
		t.Error("root has keys: no 'no keys' warning")
	}

	if got := sev("kbdinteractiveauthentication yes\npasswordauthentication no\n", true); got["ssh.password-auth"].ID == "" {
		t.Error("keyboard-interactive must count as password auth")
	}

	// Root login allowed but only with keys: not a password problem.
	if got := sev("permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication no\npermitemptypasswords yes\n", true); len(got) != 0 {
		t.Errorf("key-only server produced findings: %v", got)
	}
	hardened := "permitrootlogin without-password\npasswordauthentication no\nkbdinteractiveauthentication no\npermitemptypasswords no\n"
	if got := sev(hardened, true); len(got) != 0 {
		t.Errorf("hardened config produced findings: %v", got)
	}
}

func TestRootHasKeys(t *testing.T) {
	root := t.TempDir()
	if rootHasKeys(root) {
		t.Error("no file means no keys")
	}
	write(t, root, "root/.ssh/authorized_keys", "# only a comment\n")
	if rootHasKeys(root) {
		t.Error("comment is not a key")
	}
	write(t, root, "root/.ssh/authorized_keys", "ssh-ed25519 aGVsbG8= me@mac\n")
	if !rootHasKeys(root) {
		t.Error("key not detected")
	}
}
