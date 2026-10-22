package check

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/boxwarden/agent/finding"
)

func TestCVEs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n")
	write(t, root, "var/lib/dpkg/status", strings.Join([]string{
		"Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u1\nDescription: x\n multi-line continuation",
		"Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u1",
		"Package: libc6\nStatus: install ok installed\nSource: glibc (2.36-9)\nVersion: 2.36-9+b1",
		"Package: removed\nStatus: deinstall ok config-files\nVersion: 1.0",
	}, "\n\n")+"\n")
	// A running Alpine container, seen from the host through /proc/<pid>/root.
	id := strings.Repeat("ab", 32)
	write(t, root, "proc/555/cgroup", "0::/system.slice/docker-"+id+".scope\n")
	write(t, root, "proc/555/root/etc/os-release", "ID=alpine\nVERSION_ID=3.20.3\n")
	write(t, root, "proc/555/root/lib/apk/db/installed", "C:x\nP:busybox-binsh\nV:1.36.1-r28\no:busybox\n\nP:musl\nV:1.2.5-r0\n\n")

	vulns := map[string]string{ // id -> fixed version ("" = no fix yet)
		"DEBIAN-CVE-2024-0001":  "3.0.11-1~deb12u2",
		"DEBIAN-CVE-2024-0002":  "",
		"DEBIAN-CVE-2023-4911":  "2.36-9+deb12u3",
		"ALPINE-CVE-2023-42364": "1.36.1-r29",
	}
	eco := map[string]string{"DEBIAN": "Debian:12", "ALPINE": "Alpine:v3.20"}
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/kev":
			w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2023-4911"}]}`))
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string } `json:"package"`
					Version string                           `json:"version"`
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			hits := map[string][]string{
				"openssl": {"DEBIAN-CVE-2024-0001", "DEBIAN-CVE-2024-0002"},
				"glibc":   {"DEBIAN-CVE-2023-4911"},
				"busybox": {"ALPINE-CVE-2023-42364"},
			}
			var res []map[string]any
			for _, q := range req.Queries {
				queries = append(queries, q.Package.Ecosystem+" "+q.Package.Name+" "+q.Version)
				var vs []map[string]string
				for _, id := range hits[q.Package.Name] {
					vs = append(vs, map[string]string{"id": id})
				}
				res = append(res, map[string]any{"vulns": vs})
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			vid := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			src := map[string]string{"DEBIAN-CVE-2023-4911": "glibc", "ALPINE-CVE-2023-42364": "busybox"}[vid]
			if src == "" {
				src = "openssl"
			}
			events := []map[string]string{{"introduced": "0"}}
			if f := vulns[vid]; f != "" {
				events = append(events, map[string]string{"fixed": f})
			}
			json.NewEncoder(w).Encode(map[string]any{"id": vid, "affected": []any{
				map[string]any{"package": map[string]string{"name": src, "ecosystem": eco[strings.Split(vid, "-")[0]]}, "ranges": []any{map[string]any{"events": events}}},
				// Same CVE fixed only in Ubuntu Pro must not count for us.
				map[string]any{"package": map[string]string{"name": src, "ecosystem": "Ubuntu:Pro:22.04:LTS"}, "ranges": []any{map[string]any{"events": []any{map[string]string{"fixed": "9"}}}}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldOSV, oldKEV := osvURL, kevURL
	osvURL, kevURL = srv.URL, srv.URL+"/kev"
	defer func() { osvURL, kevURL = oldOSV, oldKEV }()

	fs, err := cves(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, q := range []string{"Debian:12 openssl 3.0.11-1~deb12u1", "Debian:12 glibc 2.36-9", "Alpine:v3.20 busybox 1.36.1-r28", "Alpine:v3.20 musl 1.2.5-r0"} {
		if !strings.Contains(strings.Join(queries, "\n"), q) {
			t.Errorf("missing query %q in %v", q, queries)
		}
	}
	if len(queries) != 4 {
		t.Errorf("openssl+libssl3 must collapse into one source query, removed packages skipped: %v", queries)
	}

	got := map[string]finding.Finding{}
	for _, f := range fs {
		got[f.Title] = f
	}
	want := map[string]finding.Severity{
		"Host: glibc 2.36-9 has actively exploited CVE-2023-4911":                              finding.Critical,
		"Host: 2 packages have security fixes available (2 vulnerabilities)":                   finding.Medium,
		"Container abababababab: 1 packages have security fixes available (1 vulnerabilities)": finding.Medium,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings: %v", len(got), got)
	}
	for title, sev := range want {
		if f, ok := got[title]; !ok || f.Severity != sev {
			t.Errorf("want %q (%s); got %v", title, sev, got)
		}
	}
	if f := got["Host: glibc 2.36-9 has actively exploited CVE-2023-4911"]; !strings.Contains(f.Fix, "--only-upgrade libc6") {
		t.Errorf("KEV fix must upgrade the binary package: %q", f.Fix)
	}
	if f := got["Container abababababab: 1 packages have security fixes available (1 vulnerabilities)"]; !strings.Contains(f.Fix, "docker compose pull") {
		t.Errorf("container fix: %q", f.Fix)
	}
}

func TestEcosystem(t *testing.T) {
	for osr, want := range map[string]string{
		"ID=ubuntu\nVERSION_ID=\"22.04\"\n": "Ubuntu:22.04:LTS",
		"ID=ubuntu\nVERSION_ID=\"24.10\"\n": "Ubuntu:24.10",
		"ID=ubuntu\nVERSION_ID=\"23.04\"\n": "Ubuntu:23.04",
		"ID=debian\n":                       "",
		"ID=fedora\nVERSION_ID=40\n":        "",
	} {
		root := t.TempDir()
		write(t, root, "etc/os-release", osr)
		if got, _ := packages(root); got != want {
			t.Errorf("%q: got %q, want %q", osr, got, want)
		}
	}
}

func TestContainerLabel(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("cd", 32)
	if got := containerLabel(root, id); got != "cdcdcdcdcdcd" {
		t.Errorf("fallback: %q", got)
	}
	write(t, root, "var/lib/docker/containers/"+id+"/config.v2.json", `{"Name":"/app-redis-1","Config":{"Image":"redis:7-alpine"}}`)
	if got := containerLabel(root, id); got != "app-redis-1 (redis:7-alpine)" {
		t.Errorf("label: %q", got)
	}
}

func TestAffectsInstalled(t *testing.T) {
	var v osvVuln
	json.Unmarshal([]byte(`{"affected":[{"package":{"name":"inetutils","ecosystem":"Ubuntu:24.04:LTS"},
		"ecosystem_specific":{"binaries":[{"binary_name":"inetutils-telnetd"}]}}]}`), &v)
	client := pkg{src: "inetutils", bins: []string{"inetutils-telnet"}}
	server := pkg{src: "inetutils", bins: []string{"inetutils-telnet", "inetutils-telnetd"}}
	if affectsInstalled(v, "Ubuntu:24.04:LTS", client) {
		t.Error("telnetd bug must not be critical when only the telnet client is installed")
	}
	if !affectsInstalled(v, "Ubuntu:24.04:LTS", server) {
		t.Error("telnetd installed: affected")
	}
	if !affectsInstalled(osvVuln{}, "Debian:12", client) {
		t.Error("no binary data (Debian): assume affected")
	}
}
