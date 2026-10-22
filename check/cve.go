package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

// OSV does version matching for Debian/Ubuntu/Alpine, so we never compare dpkg/apk versions ourselves.
// Only package names and versions leave the host (ADR-0002).
var (
	osvURL = "https://api.osv.dev"
	kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	httpc  = &http.Client{Timeout: 30 * time.Second}
)

var (
	cveRe       = regexp.MustCompile(`CVE-\d{4}-\d+`)
	containerRe = regexp.MustCompile(`[0-9a-f]{64}`)
)

// pkg is a source package: OSV tracks vulnerabilities per source, fixes ship as its binaries.
type pkg struct {
	src, ver string
	bins     []string
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// CVE checks OS packages on the host and in running containers.
func CVE() ([]finding.Finding, error) {
	return cves("/")
}

func cves(root string) ([]finding.Finding, error) {
	var feed struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := getJSON(kevURL, nil, &feed); err != nil {
		return nil, fmt.Errorf("CISA KEV: %w", err)
	}
	kev := map[string]bool{}
	for _, v := range feed.Vulnerabilities {
		kev[v.CveID] = true
	}

	targets := map[string]string{"Host": root}
	for id, pid := range containers(root) {
		targets["Container "+containerLabel(root, id)] = filepath.Join(root, "proc", pid, "root")
	}

	var fs []finding.Finding
	for name, troot := range targets {
		eco, pkgs := packages(troot)
		if eco == "" || len(pkgs) == 0 {
			continue // ponytail: Debian/Ubuntu/Alpine only, RHEL family is post-MVP
		}
		found, err := scanPackages(name, eco, pkgs, kev)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		fs = append(fs, found...)
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Title < fs[j].Title })
	return fs, nil
}

func scanPackages(target, eco string, pkgs []pkg, kev map[string]bool) ([]finding.Finding, error) {
	type query struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	ids := make([][]string, len(pkgs))
	// ponytail: ignores per-query next_page_token; a single package with >1000 open vulns is not a VPS reality.
	for start := 0; start < len(pkgs); start += 1000 {
		chunk := pkgs[start:min(start+1000, len(pkgs))]
		req := struct {
			Queries []query `json:"queries"`
		}{}
		for _, p := range chunk {
			var q query
			q.Package.Name, q.Package.Ecosystem, q.Version = p.src, eco, p.ver
			req.Queries = append(req.Queries, q)
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := getJSON(osvURL+"/v1/querybatch", req, &resp); err != nil {
			return nil, fmt.Errorf("OSV querybatch: %w", err)
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				ids[start+i] = append(ids[start+i], v.ID)
			}
		}
	}

	details, err := fetchVulns(ids)
	if err != nil {
		return nil, err
	}

	container := strings.HasPrefix(target, "Container")
	var fs []finding.Finding
	type count struct {
		src string
		n   int
	}
	var fixable []count
	total := 0
	for i, p := range pkgs {
		n := 0
		var exploited []string
		fixedIn := ""
		for _, id := range ids[i] {
			v := details[id]
			fixed := fixedVersion(v, eco, p.src)
			if fixed == "" {
				continue // no fix published yet: nothing the user can do
			}
			n++
			if cve := cveRe.FindString(id + " " + strings.Join(v.Aliases, " ")); kev[cve] {
				exploited = append(exploited, cve)
				fixedIn = fixed // ponytail: with several KEVs in one package this is the last one's fix; fine, upgrading to latest covers all
			}
		}
		if n == 0 {
			continue
		}
		fixable = append(fixable, count{p.src, n})
		total += n
		if len(exploited) > 0 {
			sort.Strings(exploited)
			fs = append(fs, finding.Finding{
				ID: "cve.kev", Severity: finding.Critical,
				Title:  target + ": " + p.src + " " + p.ver + " has actively exploited " + strings.Join(exploited, ", "),
				Detail: "Listed in CISA Known Exploited Vulnerabilities: attackers use this in the wild. Fixed in " + fixedIn + ".",
				Fix:    upgradeFix(eco, container, p.bins),
			})
		}
	}

	if len(fixable) > 0 {
		sort.Slice(fixable, func(i, j int) bool { return fixable[i].n > fixable[j].n })
		var top []string
		for _, c := range fixable[:min(10, len(fixable))] {
			top = append(top, c.src+" ("+strconv.Itoa(c.n)+")")
		}
		fs = append(fs, finding.Finding{
			ID: "cve.outdated", Severity: finding.Medium,
			Title:  fmt.Sprintf("%s: %d packages have security fixes available (%d vulnerabilities)", target, len(fixable), total),
			Detail: "Most affected: " + strings.Join(top, ", "),
			Fix:    upgradeFix(eco, container, nil),
		})
	}
	return fs, nil
}

// fixedVersion returns the fix for this exact ecosystem (so Ubuntu Pro-only fixes don't count), or "".
func fixedVersion(v osvVuln, eco, src string) string {
	for _, a := range v.Affected {
		if a.Package.Ecosystem != eco || a.Package.Name != src {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" {
					return f
				}
			}
		}
	}
	return ""
}

func upgradeFix(eco string, container bool, bins []string) string {
	switch {
	case container:
		return "Pull a newer image (or rebuild yours on a fresh base) and recreate: docker compose pull && docker compose up -d"
	case strings.HasPrefix(eco, "Alpine"):
		return "apk update && apk upgrade"
	case len(bins) > 0:
		return "sudo apt update && sudo apt install --only-upgrade " + strings.Join(bins, " ")
	default:
		return "sudo apt update && sudo apt upgrade   # and enable unattended-upgrades"
	}
}

func fetchVulns(ids [][]string) (map[string]osvVuln, error) {
	out := map[string]osvVuln{}
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
		sem      = make(chan struct{}, 16)
	)
	seen := map[string]bool{}
	for _, list := range ids {
		for _, id := range list {
			if seen[id] {
				continue
			}
			seen[id] = true
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				var v osvVuln
				err := getJSON(osvURL+"/v1/vulns/"+id, nil, &v)
				mu.Lock()
				defer mu.Unlock()
				if err != nil && firstErr == nil {
					firstErr = fmt.Errorf("OSV %s: %w", id, err)
				}
				out[id] = v
			})
		}
	}
	wg.Wait()
	return out, firstErr
}

func getJSON(url string, body, out any) error {
	method, payload := http.MethodGet, []byte(nil)
	if body != nil {
		method = http.MethodPost
		payload, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "heimdall-agent")
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// containers maps container id -> one of its pids; /proc/<pid>/root is the container's filesystem.
func containers(root string) map[string]string {
	out := map[string]string{}
	entries, _ := os.ReadDir(filepath.Join(root, "proc"))
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(root, "proc", e.Name(), "cgroup"))
		if id := containerRe.FindString(string(b)); id != "" && out[id] == "" {
			out[id] = e.Name()
		}
	}
	return out
}

// containerLabel is "name (image)" from Docker's on-disk state, or the short id when that isn't readable.
func containerLabel(root, id string) string {
	var cfg struct {
		Name   string
		Config struct{ Image string }
	}
	if json.Unmarshal([]byte(readFile(root, "var/lib/docker/containers/"+id+"/config.v2.json")), &cfg) != nil || cfg.Name == "" {
		return id[:12]
	}
	return strings.TrimPrefix(cfg.Name, "/") + " (" + cfg.Config.Image + ")"
}

// packages returns the OSV ecosystem and installed source packages of the OS under root.
func packages(root string) (string, []pkg) {
	osr := stanza(readFile(root, "etc/os-release"), "=")
	if len(osr) == 0 {
		osr = stanza(readFile(root, "usr/lib/os-release"), "=")
	}
	ver := strings.Trim(osr["VERSION_ID"], `"`)
	switch strings.Trim(osr["ID"], `"`) {
	case "debian":
		if ver == "" {
			return "", nil // testing/sid: no OSV ecosystem
		}
		return "Debian:" + ver, dpkgPackages(root)
	case "ubuntu":
		eco := "Ubuntu:" + ver
		if major, minor, _ := strings.Cut(ver, "."); minor == "04" && len(major) == 2 && (major[1]-'0')%2 == 0 {
			eco += ":LTS"
		}
		return eco, dpkgPackages(root)
	case "alpine":
		parts := strings.Split(ver, ".")
		if len(parts) < 2 {
			return "", nil
		}
		return "Alpine:v" + parts[0] + "." + parts[1], apkPackages(root)
	}
	return "", nil
}

func dpkgPackages(root string) []pkg {
	bySrc := map[string]*pkg{}
	for s := range strings.SplitSeq(readFile(root, "var/lib/dpkg/status"), "\n\n") {
		f := stanza(s, ": ")
		if f["Status"] != "install ok installed" {
			continue
		}
		src, ver := f["Package"], f["Version"]
		if s := f["Source"]; s != "" { // "Source: glibc" or "Source: glibc (2.36-9)" when versions differ
			name, v, hasVer := strings.Cut(s, " (")
			src = name
			if hasVer {
				ver = strings.TrimSuffix(v, ")")
			}
		}
		addPkg(bySrc, src, ver, f["Package"])
	}
	return sortedPkgs(bySrc)
}

func apkPackages(root string) []pkg {
	bySrc := map[string]*pkg{}
	for s := range strings.SplitSeq(readFile(root, "lib/apk/db/installed"), "\n\n") {
		f := stanza(s, ":")
		if f["P"] == "" {
			continue
		}
		src := f["o"]
		if src == "" {
			src = f["P"]
		}
		addPkg(bySrc, src, f["V"], f["P"])
	}
	return sortedPkgs(bySrc)
}

func addPkg(bySrc map[string]*pkg, src, ver, bin string) {
	if p := bySrc[src]; p != nil {
		p.bins = append(p.bins, bin)
		return
	}
	bySrc[src] = &pkg{src: src, ver: ver, bins: []string{bin}}
}

func sortedPkgs(bySrc map[string]*pkg) []pkg {
	out := make([]pkg, 0, len(bySrc))
	for _, p := range bySrc {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

// stanza parses "Key<sep>value" lines; indented continuation lines are skipped.
func stanza(s, sep string) map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(s, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(line, sep); ok {
			m[k] = v
		}
	}
	return m
}

func readFile(root, path string) string {
	b, _ := os.ReadFile(filepath.Join(root, path))
	return string(b)
}
