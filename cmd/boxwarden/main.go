package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/boxwarden/agent/check"
	"github.com/boxwarden/agent/cloud"
	"github.com/boxwarden/agent/finding"
)

var version = "dev" // set by -ldflags "-X main.version=..."

const usage = `usage:
  boxwarden scan [--json] [--checks LIST | --skip LIST] [--push]
                           run checks (all by default); --push sends the report to Boxwarden cloud
  boxwarden ports [--json]  list listening ports: who owns them, what they are, how risky
  boxwarden metrics [--json] [--push]
                           CPU, memory, disks, network, busiest processes; --push sends them to the cloud
  boxwarden baseline        record current users, keys, cron, ports... as "normal"
  boxwarden enroll [--server URL] TOKEN|-
                           connect this server to your Boxwarden account (- reads the token from stdin)`

// Check names equal finding ID prefixes ("ssh.password-auth"), so the cloud knows which findings a report covers.
var allChecks = []string{"ssh", "auth", "files", "updates", "ioc", "integrity", "docker", "tls", "exposed", "cve"}

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
	case "metrics":
		metrics(os.Args[2:])
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
	server := fl.String("server", "https://api.boxwarden.sh", "Boxwarden API URL")
	fl.Parse(args)
	if fl.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: boxwarden enroll [--server URL] TOKEN")
		os.Exit(2)
	}
	token := fl.Arg(0)
	if token == "-" { // from stdin, so it never shows up in the process list
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		token = strings.TrimSpace(string(b))
	}
	host, _ := os.Hostname()
	if err := cloud.Enroll(*server, token, host); err != nil {
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

func metrics(args []string) {
	fl := flag.NewFlagSet("metrics", flag.ExitOnError)
	asJSON := fl.Bool("json", false, "print the sample as JSON")
	push := fl.Bool("push", false, "send the sample to Boxwarden cloud")
	fl.Parse(args)

	m := check.Metrics()
	m.AgentVersion = version
	switch {
	case *push:
		if err := cloud.PushMetrics(m); err != nil {
			fmt.Fprintln(os.Stderr, "push:", err)
			os.Exit(1)
		}
	case *asJSON:
		json.NewEncoder(os.Stdout).Encode(m)
	default:
		gb := func(b uint64) string { return fmt.Sprintf("%.1f GB", float64(b)/(1<<30)) }
		fmt.Printf("load     %.2f %.2f %.2f on %d CPUs\n", m.Load[0], m.Load[1], m.Load[2], m.NumCPU)
		if m.MemTotal > 0 {
			fmt.Printf("memory   %s of %s used\n", gb(m.MemTotal-m.MemAvailable), gb(m.MemTotal))
		}
		if m.SwapTotal > 0 {
			fmt.Printf("swap     %s of %s used\n", gb(m.SwapTotal-m.SwapFree), gb(m.SwapTotal))
		}
		for _, d := range m.Disks {
			fmt.Printf("disk     %-20s %s free of %s\n", d.Mount, gb(d.Avail), gb(d.Size))
		}
		for _, p := range m.Top {
			fmt.Printf("process  %-20s %5.1f%% CPU  %s\n", p.Name, p.CPU, gb(p.RSS))
		}
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
	only := fl.String("checks", strings.Join(allChecks, ","), "comma-separated checks to run")
	skip := fl.String("skip", "", "comma-separated checks not to run")
	push := fl.Bool("push", false, "send the report to Boxwarden cloud")
	fl.Parse(args)

	selected := strings.Split(*only, ",")
	skipped := strings.Split(*skip, ",")
	for _, c := range append(slices.Clone(selected), skipped...) {
		if c != "" && !slices.Contains(allChecks, c) {
			fmt.Fprintf(os.Stderr, "unknown check %q (have %s)\n", c, strings.Join(allChecks, ","))
			os.Exit(2)
		}
	}
	selected = slices.DeleteFunc(selected, func(c string) bool { return c == "" || slices.Contains(skipped, c) })

	var inventory []check.Port // probed once, shared by `exposed` and the pushed report
	if slices.Contains(selected, "exposed") || *push {
		inventory = check.Inventory(true)
	}
	run := map[string]func() ([]finding.Finding, error){
		"ssh":       check.SSHD,
		"auth":      check.Auth,
		"files":     check.Files,
		"updates":   check.Updates,
		"ioc":       check.IOC,
		"integrity": check.Integrity,
		"docker":    check.Docker,
		"tls":       check.TLS,
		"exposed":   func() ([]finding.Finding, error) { return check.ExposedIn(inventory), nil },
		"cve":       check.CVE,
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
		for _, f := range fs {
			report.Findings = append(report.Findings, f.Cleaned())
		}
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
