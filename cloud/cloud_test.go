package cloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/boxwarden/agent/finding"
)

func TestEnrollAndPush(t *testing.T) {
	var got finding.Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll":
			var req map[string]string
			json.NewDecoder(r.Body).Decode(&req)
			if req["token"] != "tok" || req["hostname"] != "vps1" {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{"key":"srvkey"}`))
		case "/v1/report":
			if r.Header.Get("Authorization") != "Bearer srvkey" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			json.NewDecoder(r.Body).Decode(&got)
		}
	}))
	defer srv.Close()
	ConfigPath = filepath.Join(t.TempDir(), "etc", "agent.json")

	if err := Push(finding.Report{}); err == nil {
		t.Fatal("push before enroll must fail")
	}
	if err := Enroll(srv.URL, "wrong", "vps1"); err == nil {
		t.Fatal("bad token must fail")
	}
	if err := Enroll("http://evil.example", "tok", "vps1"); err == nil {
		t.Fatal("plain http to a remote host must be refused: the key would travel in clear text")
	}
	srv.URL = "http://localhost:" + srv.URL[len("http://127.0.0.1:"):]
	if err := Enroll(srv.URL, "tok", "vps1"); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(ConfigPath); info.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, want 0600", info.Mode().Perm())
	}

	r := finding.Report{Hostname: "vps1", Checks: []string{"ssh"}, Findings: []finding.Finding{{ID: "ssh.password-auth", Severity: finding.High, Title: "SSH accepts passwords"}}}
	if err := Push(r); err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "vps1" || len(got.Findings) != 1 {
		t.Errorf("server got %+v", got)
	}
}
