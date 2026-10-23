//go:build !linux

package check

import "github.com/boxwarden/agent/finding"

func statfs(string) (finding.Disk, bool) { return finding.Disk{}, false } // the agent runs on Linux only
