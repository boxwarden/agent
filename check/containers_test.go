package check

import (
	"encoding/json"
	"testing"
)

func TestContainerRisks(t *testing.T) {
	c := dockerContainer{ID: "abc", Names: []string{"/app-web-1"}, Labels: map[string]string{"com.docker.compose.service": "web"}}
	var in containerInspect
	json.Unmarshal([]byte(`{"HostConfig":{"Privileged":true,"CapAdd":["SYS_ADMIN"]},"Mounts":[
		{"Type":"bind","Source":"/var/run/docker.sock","RW":false},
		{"Type":"bind","Source":"/","RW":true},
		{"Type":"bind","Source":"/etc","RW":false},
		{"Type":"bind","Source":"/srv/app","RW":true},
		{"Type":"volume","Source":"/var/lib/docker/volumes/x/_data","RW":true}]}`), &in)

	var got []string
	for _, f := range containerRisks(c, in) {
		got = append(got, f.Key+" "+string(f.Severity))
	}
	want := []string{"docker.privileged|app-web-1 high", "docker.socket|app-web-1 medium", "docker.host-mount|app-web-1 high"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %q, want %q", got[i], want[i])
		}
	}

	in.HostConfig.Privileged, in.Mounts = false, nil
	if fs := containerRisks(c, in); len(fs) != 1 || fs[0].ID != "docker.capabilities" {
		t.Errorf("capabilities: %+v", fs)
	}
	if dockerInspectPath.MatchString("/containers/abc/json") || !dockerInspectPath.MatchString("/containers/"+"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/json") {
		t.Error("inspect allowlist")
	}
}
