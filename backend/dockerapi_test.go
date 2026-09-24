package main

import (
	"strings"
	"testing"
)

func TestValidDockerID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"0123456789ab", true},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"ABCDEF012345", true},
		{"", false},
		{"0123456789a", false},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", false},
		{"container; rm -rf /", false},
		{"$(reboot)", false},
		{"../../etc/passwd", false},
	}
	for _, c := range cases {
		if got := validDockerID(c.id); got != c.want {
			t.Errorf("validDockerID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

func TestParseDockerContainers(t *testing.T) {
	raw := strings.Join([]string{
		`{"ID":"0123456789ab","Names":"/web,/web-proxy","Image":"nginx:latest","State":"RUNNING","Status":"Up 2 hours","Ports":"0.0.0.0:80->80/tcp"}`,
		`{"ID":"abcdef012345","Names":"","Image":"busybox","State":"exited","Status":"Exited (0) 3 minutes ago","Ports":""}`,
		"",
	}, "\n")
	entries, err := parseDockerContainers(raw)
	if err != nil {
		t.Fatalf("parseDockerContainers: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2", len(entries))
	}
	if entries[0].ID != "0123456789ab" || entries[0].Names != "web" {
		t.Errorf("first entry = %+v, want ID 0123456789ab and name web", entries[0])
	}
	if entries[0].State != "running" {
		t.Errorf("state = %q, want lower-case running", entries[0].State)
	}
	if entries[1].Names != "" || entries[1].State != "exited" {
		t.Errorf("second entry = %+v", entries[1])
	}
}

func TestParseDockerImages(t *testing.T) {
	raw := `{"Repository":"nginx","Tag":"latest","ID":"sha256:0123456789abcdef0123","Size":"142MB","CreatedSince":"2 weeks ago"}
{"Repository":"<none>","Tag":"<none>","ID":"abcdef012345","Size":"7.8MB","CreatedSince":"5 days ago"}`
	entries, err := parseDockerImages(raw)
	if err != nil {
		t.Fatalf("parseDockerImages: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2", len(entries))
	}
	if entries[0].Repository != "nginx" || entries[0].Tag != "latest" {
		t.Errorf("first entry = %+v", entries[0])
	}
	if entries[0].ID != "0123456789abcdef0123" {
		t.Errorf("ID = %q, want sha256 prefix stripped", entries[0].ID)
	}
	if entries[1].Repository != "<none>" || entries[1].ID != "abcdef012345" {
		t.Errorf("second entry = %+v", entries[1])
	}
}

func TestParseDockerJSONRejectsMalformedOutput(t *testing.T) {
	if _, err := parseDockerContainers("{not json}"); err == nil {
		t.Fatal("parseDockerContainers accepted malformed JSON")
	}
	if _, err := parseDockerImages("ok"); err == nil {
		t.Fatal("parseDockerImages accepted malformed JSON")
	}
}

func TestLimitedBufferTruncatesButCompletes(t *testing.T) {
	buffer := &limitedBuffer{limit: 4}
	n, err := buffer.Write([]byte("123456"))
	if err != nil || n != 6 {
		t.Fatalf("Write = (%d, %v), want (6, nil)", n, err)
	}
	if buffer.String() != "1234" {
		t.Errorf("String = %q, want %q", buffer.String(), "1234")
	}
	if !buffer.truncated {
		t.Error("truncated was not set")
	}
}

func TestDockerCommandTimeoutHasActionableMessage(t *testing.T) {
	result := dockerCommandError(commandResult{err: errRemoteCommandTimeout}, "stop container")
	message, _ := result["message"].(string)
	if result["success"] != false {
		t.Errorf("success = %#v, want false", result["success"])
	}
	if !strings.Contains(message, "Docker stop container timed out") ||
		!strings.Contains(message, "remote Docker daemon") {
		t.Errorf("message = %q, want actionable Docker timeout guidance", message)
	}
}

func TestDockerLogsRequireSSH(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{
		"local": {id: "local", kind: "local"},
	}}
	raw, pluginErr := plug.dockerContainerLogs(map[string]any{
		"connectionId": "local",
		"id":           "0123456789ab",
	})
	if pluginErr != nil {
		t.Fatalf("dockerContainerLogs: %v", pluginErr)
	}
	result, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	if result["success"] != false {
		t.Errorf("local log request = %#v, want failure", result)
	}
}

func TestDockerDetectRequiresSSH(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{
		"local": {id: "local", kind: "local"},
	}}
	raw, pluginErr := plug.dockerDetect(map[string]any{"connectionId": "local"})
	if pluginErr != nil {
		t.Fatalf("dockerDetect: %v", pluginErr)
	}
	result, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	if result["success"] != true || result["installed"] != false {
		t.Errorf("local detection = %#v, want success and not installed", result)
	}
}

func TestParseDockerImageDetailsBundle(t *testing.T) {
	image := `{"Id":"sha256:0123456789abcdef","RepoTags":["nginx:latest","nginx:alpine"],"RepoDigests":["nginx@sha256:fedcba"],"Created":"2026-09-01T00:00:00Z","DockerVersion":"27.3.1","Architecture":"amd64","Variant":"v8","Os":"linux","Size":67784704,"Config":{"User":"","WorkingDir":"/usr/share/nginx/html","Entrypoint":["/docker-entrypoint.sh"],"Cmd":["nginx","-g","daemon off;"],"Env":["PATH=/usr/local/sbin:/usr/local/bin"],"Labels":{"org.opencontainers.image.source":"nginx"},"ExposedPorts":{"443/tcp":{},"80/tcp":{}}},"RootFS":{"Layers":["sha256:aaa","sha256:bbb"]}}`
	raw := image + "\n" + dockerImageDetailsMarker + "\n0123456789abcdef\nabcdef012345\n" + dockerImageDetailsMarker + "\n192.168.1.10 10.0.0.5\n"
	details, ids, hostIPs, err := parseDockerImageDetailsBundle(raw)
	if err != nil {
		t.Fatalf("parseDockerImageDetailsBundle: %v", err)
	}
	if details.ID != "0123456789abcdef" || details.Size != 67784704 || details.LayerCount != 2 {
		t.Errorf("details = %+v", details)
	}
	if details.Architecture != "amd64" || details.OS != "linux" || details.Variant != "v8" {
		t.Errorf("platform = %s/%s/%s", details.Architecture, details.OS, details.Variant)
	}
	if strings.Join(details.ExposedPorts, ",") != "443/tcp,80/tcp" {
		t.Errorf("exposed ports = %#v", details.ExposedPorts)
	}
	if strings.Join(ids, ",") != "0123456789abcdef,abcdef012345" {
		t.Errorf("container IDs = %#v", ids)
	}
	if strings.Join(hostIPs, ",") != "192.168.1.10,10.0.0.5" {
		t.Errorf("host IPs = %#v", hostIPs)
	}
}

func TestParseDockerImageContainers(t *testing.T) {
	raw := strings.Join([]string{
		`{"Id":"0123456789abcdef","Name":"/web","Image":"sha256:0123456789abcdef","State":{"Status":"running","Running":true},"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]},"Networks":{"frontend":{"NetworkID":"111111111111","IPAddress":"172.20.0.3","GlobalIPv6Address":"fd00::3","Gateway":"172.20.0.1","IPv6Gateway":"fd00::1"}}}}`,
		`{"Id":"abcdef012345","Name":"/worker","Image":"sha256:0123456789abcdef","State":{"Status":"exited","Running":false},"NetworkSettings":{"Ports":{},"Networks":{}}}`,
	}, "\n")
	containers, err := parseDockerImageContainers(raw)
	if err != nil {
		t.Fatalf("parseDockerImageContainers: %v", err)
	}
	if len(containers) != 2 || containers[0].Name != "web" || containers[1].Name != "worker" {
		t.Fatalf("containers = %+v", containers)
	}
	if len(containers[0].Ports) != 1 || containers[0].Ports[0].ContainerPort != "80" ||
		containers[0].Ports[0].HostIP != "0.0.0.0" || containers[0].Ports[0].HostPort != "8080" {
		t.Errorf("ports = %+v", containers[0].Ports)
	}
	if len(containers[0].Networks) != 1 || containers[0].Networks[0].Network != "frontend" ||
		containers[0].Networks[0].NetworkID != "111111111111" ||
		containers[0].Networks[0].IPAddress != "172.20.0.3" ||
		containers[0].Networks[0].Gateway != "172.20.0.1" {
		t.Errorf("networks = %+v", containers[0].Networks)
	}
}

func TestParseDockerImageDetailsRejectsMalformedBundle(t *testing.T) {
	if _, _, _, err := parseDockerImageDetailsBundle("{}"); err == nil {
		t.Fatal("parseDockerImageDetailsBundle accepted a malformed bundle")
	}
}

func TestDockerImageDetailsRequireSSH(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{
		"local": {id: "local", kind: "local"},
	}}
	raw, pluginErr := plug.dockerImageDetails(map[string]any{
		"connectionId": "local",
		"id":           "0123456789ab",
	})
	if pluginErr != nil {
		t.Fatalf("dockerImageDetails: %v", pluginErr)
	}
	result, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	if result["success"] != false {
		t.Errorf("local image details = %#v, want failure", result)
	}
}

func TestParseDockerContainerDetailsBundle(t *testing.T) {
	container := `{"Id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","Name":"/web","Image":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","Created":"2026-09-20T01:02:03Z","Path":"/docker-entrypoint.sh","Args":["nginx","-g","daemon off;"],"Platform":"linux","LogPath":"/var/log/json.log","RestartCount":2,"State":{"Status":"running","Running":true,"Pid":4321,"ExitCode":0,"StartedAt":"2026-09-20T01:02:04Z","FinishedAt":"0001-01-01T00:00:00Z","Health":{"Status":"healthy","ExitCode":0}},"Config":{"Hostname":"abc123","User":"1000","WorkingDir":"/usr/share/nginx/html","Image":"nginx:latest","Entrypoint":["/docker-entrypoint.sh"],"Cmd":["nginx","-g","daemon off;"],"Env":["PATH=/usr/local/sbin"],"Labels":{"app":"web"},"ExposedPorts":{"80/tcp":{}}},"HostConfig":{"NetworkMode":"frontend","Privileged":false,"ReadonlyRootfs":true,"RestartPolicy":{"Name":"always"}},"Mounts":[{"Type":"bind","Source":"/host/web","Destination":"/usr/share/nginx/html","Mode":"rw","RW":true,"Propagation":"rprivate"}],"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]},"Networks":{"frontend":{"NetworkID":"111111111111","IPAddress":"172.20.0.3","Gateway":"172.20.0.1"}}}}`
	raw := container + "\n" + dockerContainerDetailsMarker + "\n192.168.1.10 10.0.0.5\n"
	details, hostIPs, err := parseDockerContainerDetailsBundle(raw)
	if err != nil {
		t.Fatalf("parseDockerContainerDetailsBundle: %v", err)
	}
	if details.Name != "web" || details.Image != "nginx:latest" || details.RestartCount != 2 {
		t.Errorf("details = %+v", details)
	}
	if !details.State.Running || details.State.HealthStatus != "healthy" || details.State.PID != 4321 {
		t.Errorf("state = %+v", details.State)
	}
	if details.RestartPolicy != "always" || details.NetworkMode != "frontend" || !details.ReadonlyRootfs {
		t.Errorf("runtime config = %+v", details)
	}
	if len(details.Ports) != 1 || details.Ports[0].HostPort != "8080" ||
		len(details.Networks) != 1 || details.Networks[0].IPAddress != "172.20.0.3" {
		t.Errorf("runtime networking = ports=%+v networks=%+v", details.Ports, details.Networks)
	}
	if len(details.Mounts) != 1 || details.Mounts[0].Destination != "/usr/share/nginx/html" {
		t.Errorf("mounts = %+v", details.Mounts)
	}
	if strings.Join(hostIPs, ",") != "192.168.1.10,10.0.0.5" {
		t.Errorf("host IPs = %#v", hostIPs)
	}
}

func TestParseDockerContainerDetailsRejectsMalformedBundle(t *testing.T) {
	if _, _, err := parseDockerContainerDetailsBundle("{}"); err == nil {
		t.Fatal("parseDockerContainerDetailsBundle accepted a malformed bundle")
	}
}

func TestDockerContainerDetailsRequireSSH(t *testing.T) {
	plug := &plugin{sessions: map[string]*shellSession{
		"local": {id: "local", kind: "local"},
	}}
	raw, pluginErr := plug.dockerContainerDetails(map[string]any{
		"connectionId": "local",
		"id":           "0123456789ab",
	})
	if pluginErr != nil {
		t.Fatalf("dockerContainerDetails: %v", pluginErr)
	}
	result, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", raw)
	}
	if result["success"] != false {
		t.Errorf("local container details = %#v, want failure", result)
	}
}

func TestDockerPermissionDenied(t *testing.T) {
	cases := []struct {
		name   string
		result commandResult
		want   bool
	}{
		{
			name:   "socket permission denied",
			result: commandResult{exitCode: 1, stderr: `Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock`},
			want:   true,
		},
		{
			name:   "daemon permission denied",
			result: commandResult{exitCode: 1, stdout: `Cannot connect to the Docker daemon: permission denied`},
			want:   true,
		},
		{
			name:   "unrelated docker error",
			result: commandResult{exitCode: 1, stderr: "No such container: missing"},
			want:   false,
		},
		{
			name:   "transport error is not escalated",
			result: commandResult{err: errRemoteCommandTimeout, stderr: "permission denied docker.sock"},
			want:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dockerPermissionDenied(c.result); got != c.want {
				t.Errorf("dockerPermissionDenied() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDockerCommandMessageExplainsPermissionDenied(t *testing.T) {
	message := dockerCommandMessage(commandResult{
		exitCode: 1,
		stderr:   "permission denied while trying to connect to the Docker daemon socket",
	})
	for _, expected := range []string{"SSH user", "docker group", "su in the terminal"} {
		if !strings.Contains(message, expected) {
			t.Errorf("message %q does not contain %q", message, expected)
		}
	}
}
