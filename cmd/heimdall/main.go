package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/d3f4u1t/heimdall-agent/check"
	"github.com/d3f4u1t/heimdall-agent/cloud"
	"github.com/d3f4u1t/heimdall-agent/finding"
)

var version = "dev" // set by -ldflags "-X main.version=..."

const usage = `usage:
  heimdall scan [--json] [--checks ssh,ioc,exposed,cve] [--push]
                           run checks; --push sends the report to Heimdall cloud
  heimdall ports [--json]  list listening ports: who owns them, what they are, how risky
  heimdall baseline        record current users, keys, cron, ports... as "normal"
  heimdall enroll --server URL TOKEN
                           connect this server to your Heimdall account`

// Check names equal finding ID prefixes ("ssh.password-auth"), so the cloud knows which findings a report covers.
var allChecks = []string{"ssh", "ioc", "exposed", "cve"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		scan(os.Args[2:])
	case "ports":
		ports(os.Args[2:])
	case "baseline":
		baseline()
	case "enroll":
		enroll(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

func enroll(args []string) {
	fl := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fl.String("server", "", "Heimdall URL, e.g. https://app.example.com")
	fl.Parse(args)
	if *server == "" || fl.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: heimdall enroll --server URL TOKEN")
		os.Exit(2)
	}
	host, _ := os.Hostname()
	if err := cloud.Enroll(*server, fl.Arg(0), host); err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Enrolled %s. Key saved to %s.\n", host, cloud.ConfigPath)
	if _, err := os.Stat(check.BaselinePath); os.IsNotExist(err) {
		baseline()
	}
}

func ports(args []string) {
	fl := flag.NewFlagSet("ports", flag.ExitOnError)
	asJSON := fl.Bool("json", false, "print ports as JSON")
	fl.Parse(args)

	ps := check.Inventory(true)
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(ps)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ADDRESS\tOWNER\tSERVICE\tRISK")
	for _, p := range ps {
		svc := p.Service
		if !p.Public {
			svc = "(local only)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Addr, p.Owner(), svc, p.Risk())
	}
	w.Flush()
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
	only := fl.String("checks", strings.Join(allChecks, ","), "comma-separated checks to run")
	push := fl.Bool("push", false, "send the report to Heimdall cloud")
	fl.Parse(args)

	selected := strings.Split(*only, ",")
	for _, c := range selected {
		if !slices.Contains(allChecks, c) {
			fmt.Fprintf(os.Stderr, "unknown check %q (have %s)\n", c, strings.Join(allChecks, ","))
			os.Exit(2)
		}
	}

	var inventory []check.Port // probed once, shared by `exposed` and the pushed report
	if slices.Contains(selected, "exposed") || *push {
		inventory = check.Inventory(true)
	}
	run := map[string]func() ([]finding.Finding, error){
		"ssh":     check.SSHD,
		"ioc":     check.IOC,
		"exposed": func() ([]finding.Finding, error) { return check.ExposedIn(inventory), nil },
		"cve":     check.CVE,
	}

	report := finding.Report{AgentVersion: version, Findings: []finding.Finding{}}
	report.Hostname, _ = os.Hostname()
	failed := false
	for _, name := range selected {
		fs, err := run[name]()
		if err != nil {
			fmt.Fprintf(os.Stderr, "check %s: %v\n", name, err)
			failed = true
			continue
		}
		report.Checks = append(report.Checks, name)
		report.Findings = append(report.Findings, fs...)
	}
	sort.SliceStable(report.Findings, func(i, j int) bool { return rank(report.Findings[i]) < rank(report.Findings[j]) })

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(report.Findings)
	} else if !*push {
		for _, f := range report.Findings {
			fmt.Printf("[%s] %s\n", f.Severity, f.Title)
			if f.Detail != "" {
				fmt.Printf("  %s\n", f.Detail)
			}
			fmt.Printf("  fix: %s\n\n", f.Fix)
		}
		fmt.Printf("%d finding(s)\n", len(report.Findings))
	}

	if *push {
		report.Ports, _ = json.Marshal(inventory)
		if err := cloud.Push(report); err != nil {
			fmt.Fprintln(os.Stderr, "push:", err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func rank(f finding.Finding) int {
	return slices.Index([]finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low}, f.Severity)
}
