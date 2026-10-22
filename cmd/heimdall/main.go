package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/d3f4u1t/heimdall-agent/check"
	"github.com/d3f4u1t/heimdall-agent/finding"
)

const usage = `usage:
  heimdall scan [--json]   run all checks
  heimdall baseline        record current users, keys, cron, ports... as "normal"`

var checks = map[string]func() ([]finding.Finding, error){
	"sshd":    check.SSHD,
	"ioc":     check.IOC,
	"exposed": check.Exposed,
	"cve":     check.CVE,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		scan(os.Args[2:])
	case "baseline":
		baseline()
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

func baseline() {
	snap := check.Collect("/")
	if err := check.SaveBaseline(check.BaselinePath, snap); err != nil {
		fmt.Fprintln(os.Stderr, "save baseline:", err, "(run as root)")
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(snap)
	fmt.Fprintf(os.Stderr, "\nBaseline saved to %s.\n"+
		"Review the list above NOW: if this server is already compromised, the backdoor is in it.\n"+
		"Any user, key, cron job, unit, SUID binary or port you don't recognize is a red flag.\n", check.BaselinePath)
}

func scan(args []string) {
	fl := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fl.Bool("json", false, "print findings as JSON")
	fl.Parse(args)

	all := []finding.Finding{}
	failed := false
	for name, run := range checks {
		fs, err := run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "check %s: %v\n", name, err)
			failed = true
			continue
		}
		all = append(all, fs...)
	}

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(all)
	} else {
		for _, f := range all {
			fmt.Printf("[%s] %s\n", f.Severity, f.Title)
			if f.Detail != "" {
				fmt.Printf("  %s\n", f.Detail)
			}
			fmt.Printf("  fix: %s\n\n", f.Fix)
		}
		fmt.Printf("%d finding(s)\n", len(all))
	}

	if failed {
		os.Exit(1)
	}
}
