package check

import "testing"

func TestSSHDFindings(t *testing.T) {
	ids := func(cfg string) map[string]bool {
		m := map[string]bool{}
		for _, f := range sshdFindings(cfg) {
			m[f.ID] = true
		}
		return m
	}

	bad := ids("permitrootlogin yes\nPasswordAuthentication yes\npermitemptypasswords yes\n")
	for _, id := range []string{"ssh.root-password-login", "ssh.password-auth", "ssh.empty-passwords"} {
		if !bad[id] {
			t.Errorf("missing %s", id)
		}
	}

	if got := ids("kbdinteractiveauthentication yes\npasswordauthentication no\n"); !got["ssh.password-auth"] {
		t.Error("keyboard-interactive must count as password auth")
	}

	hardened := "permitrootlogin without-password\npasswordauthentication no\nkbdinteractiveauthentication no\npermitemptypasswords no\n"
	if got := ids(hardened); len(got) != 0 {
		t.Errorf("hardened config produced findings: %v", got)
	}
}
