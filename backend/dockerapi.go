package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

const (
	dockerCommandOutputLimit = 4 * 1024 * 1024
	dockerErrorOutputLimit   = 64 * 1024
	// Detection only checks whether the executable is on the ordinary SSH
	// user's PATH; no Docker daemon request or root escalation is involved.
	dockerDetectTimeout = 10 * time.Second
	// Listing and version reads normally finish in under a second; keep a
	// short ceiling so a stuck daemon does not leave the panel hanging.
	dockerReadTimeout = 10 * time.Second
	// `docker stop -t 10` and `docker restart -t 10` can legitimately use the
	// full Docker grace period before returning.
	dockerActionTimeout          = 60 * time.Second
	dockerImageDetailsMarker     = "__NINTYSHELL_DOCKER_IMAGE_DETAILS_6E4C9A__"
	dockerContainerDetailsMarker = "__NINTYSHELL_DOCKER_CONTAINER_DETAILS_6E4C9A__"
)

type dockerContainer struct {
	ID     string `json:"id"`
	Names  string `json:"names"`
	Image  string `json:"image"`
	State  string `json:"state"`
	Status string `json:"status"`
	Ports  string `json:"ports"`
}

type dockerImage struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	ID         string `json:"id"`
	Size       string `json:"size"`
	Created    string `json:"created"`
}

type dockerImageDetails struct {
	ID            string                 `json:"id"`
	RepoTags      []string               `json:"repoTags"`
	RepoDigests   []string               `json:"repoDigests"`
	Created       string                 `json:"created"`
	DockerVersion string                 `json:"dockerVersion"`
	Architecture  string                 `json:"architecture"`
	Variant       string                 `json:"variant"`
	OS            string                 `json:"os"`
	Size          int64                  `json:"size"`
	LayerCount    int                    `json:"layerCount"`
	User          string                 `json:"user"`
	WorkingDir    string                 `json:"workingDir"`
	Entrypoint    []string               `json:"entrypoint"`
	Cmd           []string               `json:"cmd"`
	Env           []string               `json:"env"`
	Labels        map[string]string      `json:"labels"`
	ExposedPorts  []string               `json:"exposedPorts"`
	HostIPs       []string               `json:"hostIPs"`
	Containers    []dockerImageContainer `json:"containers"`
}

type dockerImageContainer struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Image    string                 `json:"image"`
	State    string                 `json:"state"`
	Status   string                 `json:"status"`
	Ports    []dockerPortMapping    `json:"ports"`
	Networks []dockerNetworkAddress `json:"networks"`
}

type dockerPortMapping struct {
	ContainerPort string `json:"containerPort"`
	HostIP        string `json:"hostIp"`
	HostPort      string `json:"hostPort"`
	Protocol      string `json:"protocol"`
}

type dockerNetworkAddress struct {
	NetworkID   string `json:"networkId"`
	Network     string `json:"network"`
	IPAddress   string `json:"ipAddress"`
	GlobalIPv6  string `json:"globalIpv6"`
	Gateway     string `json:"gateway"`
	IPv6Gateway string `json:"ipv6Gateway"`
}

type dockerContainerDetails struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Image          string                 `json:"image"`
	ImageID        string                 `json:"imageId"`
	Created        string                 `json:"created"`
	Path           string                 `json:"path"`
	Args           []string               `json:"args"`
	Hostname       string                 `json:"hostname"`
	Platform       string                 `json:"platform"`
	LogPath        string                 `json:"logPath"`
	User           string                 `json:"user"`
	WorkingDir     string                 `json:"workingDir"`
	Entrypoint     []string               `json:"entrypoint"`
	Cmd            []string               `json:"cmd"`
	Env            []string               `json:"env"`
	Labels         map[string]string      `json:"labels"`
	ExposedPorts   []string               `json:"exposedPorts"`
	State          dockerContainerState   `json:"state"`
	RestartPolicy  string                 `json:"restartPolicy"`
	RestartCount   int                    `json:"restartCount"`
	NetworkMode    string                 `json:"networkMode"`
	Privileged     bool                   `json:"privileged"`
	ReadonlyRootfs bool                   `json:"readonlyRootfs"`
	Ports          []dockerPortMapping    `json:"ports"`
	Networks       []dockerNetworkAddress `json:"networks"`
	HostIPs        []string               `json:"hostIPs"`
	Mounts         []dockerContainerMount `json:"mounts"`
}

type dockerContainerState struct {
	Status         string `json:"status"`
	Running        bool   `json:"running"`
	Paused         bool   `json:"paused"`
	Restarting     bool   `json:"restarting"`
	OOMKilled      bool   `json:"oomKilled"`
	Dead           bool   `json:"dead"`
	PID            int    `json:"pid"`
	ExitCode       int    `json:"exitCode"`
	Error          string `json:"error"`
	StartedAt      string `json:"startedAt"`
	FinishedAt     string `json:"finishedAt"`
	HealthStatus   string `json:"healthStatus"`
	HealthExitCode int    `json:"healthExitCode"`
}

type dockerContainerMount struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation"`
}

type commandResult struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

var errRemoteCommandTimeout = errors.New("remote command timed out")

// limitedBuffer keeps a hostile or accidentally noisy remote command from
// flooding the plugin bridge. Write still reports the original length so the
// remote command can finish normally; the excess is discarded locally.
type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	total := len(p)
	if remaining := b.limit - b.buffer.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
			b.truncated = true
		}
		_, _ = b.buffer.Write(p)
	} else if total > 0 {
		b.truncated = true
	}
	return total, nil
}

func (b *limitedBuffer) String() string {
	return b.buffer.String()
}

// runSSHCommand keeps the existing shell-operation timeout for callers that do
// not need a Docker-specific deadline.
func runSSHCommand(s *shellSession, command string) commandResult {
	return runSSHCommandWithTimeout(s, command, sshOpTimeout)
}

// runSSHCommandWithTimeout runs a non-interactive command on its own SSH
// channel. The interactive PTY is untouched, so Docker actions never echo into
// the shell.
func runSSHCommandWithTimeout(s *shellSession, command string, timeout time.Duration) commandResult {
	if s == nil || s.kind != "ssh" {
		return commandResult{err: errors.New("command requires an SSH connection")}
	}
	if s.isDead() {
		return commandResult{err: errors.New(s.deadError())}
	}
	if s.sshClient == nil {
		return commandResult{err: errors.New("SSH client is closed")}
	}
	session, sessionErr := withTimeout(sshDialTimeout, func() (*ssh.Session, error) {
		return s.sshClient.NewSession()
	})
	if sessionErr != nil {
		s.markDead()
		return commandResult{err: fmt.Errorf("open SSH session: %w", sessionErr)}
	}
	defer session.Close()

	stdout := &limitedBuffer{limit: dockerCommandOutputLimit}
	stderr := &limitedBuffer{limit: dockerErrorOutputLimit}
	session.Stdout = stdout
	session.Stderr = stderr

	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var runErr error
	select {
	case runErr = <-done:
	case <-timer.C:
		// Closing only this exec channel leaves the SSH connection and the
		// interactive shell alive (for example when the Docker daemon hangs).
		_ = session.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		return commandResult{
			stdout: stdout.String(),
			stderr: stderr.String(),
			err:    fmt.Errorf("remote command timed out after %s: %w", timeout, errRemoteCommandTimeout),
		}
	}

	result := commandResult{stdout: stdout.String(), stderr: stderr.String()}
	if stdout.truncated {
		result.err = errors.New("remote command output exceeded 4 MB")
		return result
	}
	if runErr == nil {
		return result
	}
	var exitErr *ssh.ExitError
	if errors.As(runErr, &exitErr) {
		result.exitCode = exitErr.ExitStatus()
		return result
	}
	// Only a non-exit SSH error can mean the transport itself is gone.
	s.markDead()
	result.err = fmt.Errorf("run remote command: %w", runErr)
	return result
}

// dockerPermissionDenied identifies the common unprivileged Docker socket
// error. The retry below is deliberately limited to this case so normal
// command failures are never escalated.
func dockerPermissionDenied(result commandResult) bool {
	if result.err != nil || result.exitCode == 0 {
		return false
	}
	message := strings.ToLower(result.stderr + "\n" + result.stdout)
	return strings.Contains(message, "permission denied") &&
		(strings.Contains(message, "docker.sock") ||
			strings.Contains(message, "docker daemon") ||
			strings.Contains(message, "connect: permission denied"))
}

// runDockerCommand deliberately runs exactly as the connected SSH user. It
// never invokes su or sudo, so Docker permissions always match the SSH
// connection. Manually running su in the terminal does not change this.
func runDockerCommand(s *shellSession, command string, timeout time.Duration) commandResult {
	return runSSHCommandWithTimeout(s, command, timeout)
}

// dockerDetect reports whether the docker executable exists on the remote
// host. The daemon does not need to be reachable for this to be true.
func (p *plugin) dockerDetect(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": true, "installed": false}, nil
	}
	result := runSSHCommandWithTimeout(current, `if command -v docker >/dev/null 2>&1; then printf installed; else printf missing; fi`, dockerDetectTimeout)
	if result.err != nil {
		return dockerCommandError(result, "detection"), nil
	}
	if result.exitCode != 0 {
		message := strings.TrimSpace(result.stderr)
		if message == "" {
			message = fmt.Sprintf("Docker detection failed with exit code %d", result.exitCode)
		}
		return map[string]any{"success": false, "installed": false, "message": message}, nil
	}
	return map[string]any{
		"success":   true,
		"installed": strings.TrimSpace(result.stdout) == "installed",
	}, nil
}

func (p *plugin) dockerOverview(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": false, "installed": false, "message": "Docker panel requires an SSH connection"}, nil
	}

	detect := runSSHCommandWithTimeout(current, `if command -v docker >/dev/null 2>&1; then printf installed; else printf missing; fi`, dockerDetectTimeout)
	if detect.err != nil {
		return dockerCommandError(detect, "detection"), nil
	}
	if detect.exitCode != 0 || strings.TrimSpace(detect.stdout) != "installed" {
		return map[string]any{
			"success":    true,
			"installed":  false,
			"containers": []dockerContainer{},
			"images":     []dockerImage{},
		}, nil
	}

	version := runDockerCommand(current, `docker version --format '{{.Client.Version}}|{{if .Server}}{{.Server.Version}}{{end}}'`, dockerReadTimeout)
	if version.err != nil {
		return dockerCommandError(version, "version check"), nil
	}
	if version.exitCode != 0 {
		message := dockerCommandMessage(version)
		parts := strings.SplitN(strings.TrimSpace(version.stdout), "|", 2)
		return map[string]any{
			"success":       true,
			"installed":     true,
			"daemon":        false,
			"clientVersion": strings.TrimSpace(parts[0]),
			"message":       message,
			"containers":    []dockerContainer{},
			"images":        []dockerImage{},
		}, nil
	}
	parts := strings.SplitN(strings.TrimSpace(version.stdout), "|", 2)
	clientVersion := strings.TrimSpace(parts[0])
	serverVersion := ""
	if len(parts) == 2 {
		serverVersion = strings.TrimSpace(parts[1])
	}

	containersResult := runDockerCommand(current, `docker ps -a --format '{{json .}}'`, dockerReadTimeout)
	if containersResult.err != nil {
		return dockerCommandError(containersResult, "container list"), nil
	}
	if containersResult.exitCode != 0 {
		return dockerResultError(dockerCommandMessage(containersResult)), nil
	}
	containers, parseErr := parseDockerContainers(containersResult.stdout)
	if parseErr != nil {
		return dockerResultError(parseErr.Error()), nil
	}

	imagesResult := runDockerCommand(current, `docker images --format '{{json .}}'`, dockerReadTimeout)
	if imagesResult.err != nil {
		return dockerCommandError(imagesResult, "image list"), nil
	}
	if imagesResult.exitCode != 0 {
		return dockerResultError(dockerCommandMessage(imagesResult)), nil
	}
	images, parseErr := parseDockerImages(imagesResult.stdout)
	if parseErr != nil {
		return dockerResultError(parseErr.Error()), nil
	}

	return map[string]any{
		"success":       true,
		"installed":     true,
		"daemon":        true,
		"clientVersion": clientVersion,
		"serverVersion": serverVersion,
		"containers":    containers,
		"images":        images,
	}, nil
}

func (p *plugin) dockerContainerAction(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": false, "message": "Docker actions require an SSH connection"}, nil
	}
	id := stringField(values, "id")
	if !validDockerID(id) {
		return map[string]any{"success": false, "message": "Invalid Docker container ID"}, nil
	}
	action := stringField(values, "action")
	var command string
	switch action {
	case "start":
		command = "docker start " + id
	case "stop":
		command = "docker stop -t 10 " + id
	case "restart":
		command = "docker restart -t 10 " + id
	case "remove":
		// Deliberately no --force: the UI only offers removal for stopped
		// containers, and the backend refuses to turn this into a kill.
		command = "docker rm " + id
	default:
		return map[string]any{"success": false, "message": "Unsupported container action"}, nil
	}
	result := runDockerCommand(current, command, dockerActionTimeout)
	if result.err != nil {
		return dockerCommandError(result, action+" container"), nil
	}
	if result.exitCode != 0 {
		return dockerResultError(dockerCommandMessage(result)), nil
	}
	return map[string]any{"success": true, "action": action, "id": id}, nil
}

func (p *plugin) dockerContainerDetails(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": false, "message": "Docker container details require an SSH connection"}, nil
	}
	id := stringField(values, "id")
	if !validDockerID(id) {
		return map[string]any{"success": false, "message": "Invalid Docker container ID"}, nil
	}

	// Container inspection and host addresses share one SSH round trip so the
	// details modal can render both without a second visible loading step.
	command := "docker inspect --format '{{json .}}' " + id +
		" && printf '\\n" + dockerContainerDetailsMarker + "\\n'" +
		" && { hostname -I 2>/dev/null || true; }"
	result := runDockerCommand(current, command, dockerReadTimeout)
	if result.err != nil {
		return dockerCommandError(result, "container details"), nil
	}
	if result.exitCode != 0 {
		return dockerResultError(dockerCommandMessage(result)), nil
	}
	details, hostIPs, parseErr := parseDockerContainerDetailsBundle(result.stdout)
	if parseErr != nil {
		return dockerResultError(parseErr.Error()), nil
	}
	details.HostIPs = hostIPs
	return map[string]any{
		"success": true,
		"id":      details.ID,
		"details": details,
	}, nil
}

func (p *plugin) dockerContainerLogs(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": false, "message": "Docker logs require an SSH connection"}, nil
	}
	id := stringField(values, "id")
	if !validDockerID(id) {
		return map[string]any{"success": false, "message": "Invalid Docker container ID"}, nil
	}
	// Keep the read bounded and include timestamps so the panel is useful for
	// diagnosing a container without attaching a potentially endless stream.
	result := runDockerCommand(current, "docker logs --tail 200 --timestamps "+id+" 2>&1", dockerReadTimeout)
	if result.err != nil {
		return dockerCommandError(result, "container logs"), nil
	}
	if result.exitCode != 0 {
		return dockerResultError(dockerCommandMessage(result)), nil
	}
	return map[string]any{
		"success": true,
		"id":      id,
		"logs":    result.stdout,
	}, nil
}

func (p *plugin) dockerImageAction(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": false, "message": "Docker actions require an SSH connection"}, nil
	}
	id := stringField(values, "id")
	if !validDockerID(id) {
		return map[string]any{"success": false, "message": "Invalid Docker image ID"}, nil
	}
	action := stringField(values, "action")
	if action != "remove" {
		return map[string]any{"success": false, "message": "Unsupported image action"}, nil
	}
	result := runDockerCommand(current, "docker image rm "+id, dockerActionTimeout)
	if result.err != nil {
		return dockerCommandError(result, "image removal"), nil
	}
	if result.exitCode != 0 {
		return dockerResultError(dockerCommandMessage(result)), nil
	}
	return map[string]any{"success": true, "action": action, "id": id}, nil
}

// dockerImageDetails returns image metadata together with the runtime facts
// that only exist on its containers: published ports, container/gateway IPs,
// and the addresses of the Docker host itself.
func (p *plugin) dockerImageDetails(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	if current.kind != "ssh" {
		return map[string]any{"success": false, "message": "Docker image details require an SSH connection"}, nil
	}
	id := stringField(values, "id")
	if !validDockerID(id) {
		return map[string]any{"success": false, "message": "Invalid Docker image ID"}, nil
	}

	// Keep image metadata, its container IDs, and host addresses on one SSH
	// round trip so opening the details modal stays fast.
	summaryCommand := "docker image inspect --format '{{json .}}' " + id +
		" && printf '\\n" + dockerImageDetailsMarker + "\\n'" +
		" && docker ps -a --filter ancestor=" + id + " --format '{{.ID}}'" +
		" && printf '\\n" + dockerImageDetailsMarker + "\\n'" +
		" && { hostname -I 2>/dev/null || true; }"
	summaryResult := runDockerCommand(current, summaryCommand, dockerReadTimeout)
	if summaryResult.err != nil {
		return dockerCommandError(summaryResult, "image details"), nil
	}
	if summaryResult.exitCode != 0 {
		return dockerResultError(dockerCommandMessage(summaryResult)), nil
	}
	details, containerIDs, hostIPs, parseErr := parseDockerImageDetailsBundle(summaryResult.stdout)
	if parseErr != nil {
		return dockerResultError(parseErr.Error()), nil
	}
	details.HostIPs = hostIPs

	if len(containerIDs) > 0 {
		inspectCommand := "docker inspect --format '{{json .}}' " + strings.Join(containerIDs, " ")
		inspectResult := runDockerCommand(current, inspectCommand, dockerReadTimeout)
		if inspectResult.err != nil {
			return dockerCommandError(inspectResult, "container details"), nil
		}
		if inspectResult.exitCode != 0 {
			return dockerResultError(dockerCommandMessage(inspectResult)), nil
		}
		containers, containersErr := parseDockerImageContainers(inspectResult.stdout)
		if containersErr != nil {
			return dockerResultError(containersErr.Error()), nil
		}
		details.Containers = containers
	}

	return map[string]any{
		"success": true,
		"id":      id,
		"details": details,
	}, nil
}

// validDockerID accepts only the hex IDs emitted by Docker (12-64 chars).
// Nothing else can enter a command string.
func validDockerID(value string) bool {
	if len(value) < 12 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		isHex := (char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'f') ||
			(char >= 'A' && char <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func parseDockerContainers(raw string) ([]dockerContainer, error) {
	entries := make([]dockerContainer, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var value map[string]string
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			return nil, fmt.Errorf("cannot parse Docker container data: %w", err)
		}
		names := strings.TrimSpace(value["Names"])
		names = strings.TrimPrefix(names, "/")
		if index := strings.Index(names, ","); index >= 0 {
			names = strings.TrimSpace(names[:index])
		}
		id := strings.TrimPrefix(strings.TrimSpace(value["ID"]), "sha256:")
		entries = append(entries, dockerContainer{
			ID:     id,
			Names:  names,
			Image:  strings.TrimSpace(value["Image"]),
			State:  strings.ToLower(strings.TrimSpace(value["State"])),
			Status: strings.TrimSpace(value["Status"]),
			Ports:  strings.TrimSpace(value["Ports"]),
		})
	}
	return entries, nil
}

func parseDockerImages(raw string) ([]dockerImage, error) {
	entries := make([]dockerImage, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var value map[string]string
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			return nil, fmt.Errorf("cannot parse Docker image data: %w", err)
		}
		entries = append(entries, dockerImage{
			Repository: strings.TrimSpace(value["Repository"]),
			Tag:        strings.TrimSpace(value["Tag"]),
			ID:         strings.TrimPrefix(strings.TrimSpace(value["ID"]), "sha256:"),
			Size:       strings.TrimSpace(value["Size"]),
			Created:    strings.TrimSpace(value["CreatedSince"]),
		})
	}
	return entries, nil
}

type rawDockerImageInspection struct {
	ID            string   `json:"Id"`
	RepoTags      []string `json:"RepoTags"`
	RepoDigests   []string `json:"RepoDigests"`
	Created       string   `json:"Created"`
	DockerVersion string   `json:"DockerVersion"`
	Architecture  string   `json:"Architecture"`
	Variant       string   `json:"Variant"`
	OS            string   `json:"Os"`
	Size          int64    `json:"Size"`
	Author        string   `json:"Author"`
	Config        *struct {
		User         string              `json:"User"`
		WorkingDir   string              `json:"WorkingDir"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		Env          []string            `json:"Env"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	RootFS struct {
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
}

func parseDockerImageDetailsBundle(raw string) (dockerImageDetails, []string, []string, error) {
	parts := strings.Split(raw, dockerImageDetailsMarker)
	if len(parts) != 3 {
		return dockerImageDetails{}, nil, nil, errors.New("cannot parse Docker image details response")
	}
	details, imageErr := parseDockerImageInspection(parts[0])
	if imageErr != nil {
		return dockerImageDetails{}, nil, nil, imageErr
	}

	ids := make([]string, 0)
	for _, line := range strings.Split(parts[1], "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		if !validDockerID(id) {
			return dockerImageDetails{}, nil, nil, errors.New("Docker returned an invalid container ID")
		}
		ids = append(ids, id)
	}
	return details, ids, strings.Fields(parts[2]), nil
}

func parseDockerImageInspection(raw string) (dockerImageDetails, error) {
	var inspection rawDockerImageInspection
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &inspection); err != nil {
		return dockerImageDetails{}, fmt.Errorf("cannot parse Docker image inspection: %w", err)
	}
	if !validDockerID(strings.TrimPrefix(strings.TrimSpace(inspection.ID), "sha256:")) {
		return dockerImageDetails{}, errors.New("Docker image inspection returned an invalid image ID")
	}

	details := dockerImageDetails{
		ID:            strings.TrimPrefix(strings.TrimSpace(inspection.ID), "sha256:"),
		RepoTags:      nonEmptyStrings(inspection.RepoTags),
		RepoDigests:   nonEmptyStrings(inspection.RepoDigests),
		Created:       strings.TrimSpace(inspection.Created),
		DockerVersion: strings.TrimSpace(inspection.DockerVersion),
		Architecture:  strings.TrimSpace(inspection.Architecture),
		Variant:       strings.TrimSpace(inspection.Variant),
		OS:            strings.TrimSpace(inspection.OS),
		Size:          inspection.Size,
		LayerCount:    len(inspection.RootFS.Layers),
		Labels:        map[string]string{},
		ExposedPorts:  []string{},
		HostIPs:       []string{},
		Containers:    []dockerImageContainer{},
	}
	if inspection.Config != nil {
		details.User = strings.TrimSpace(inspection.Config.User)
		details.WorkingDir = strings.TrimSpace(inspection.Config.WorkingDir)
		details.Entrypoint = nonEmptyStrings(inspection.Config.Entrypoint)
		details.Cmd = nonEmptyStrings(inspection.Config.Cmd)
		details.Env = nonEmptyStrings(inspection.Config.Env)
		for key, value := range inspection.Config.Labels {
			details.Labels[key] = value
		}
		for port := range inspection.Config.ExposedPorts {
			port = strings.TrimSpace(port)
			if port != "" {
				details.ExposedPorts = append(details.ExposedPorts, port)
			}
		}
		sort.Strings(details.ExposedPorts)
	}
	sort.Strings(details.RepoTags)
	sort.Strings(details.RepoDigests)
	return details, nil
}

type rawDockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type rawDockerNetworkAttachment struct {
	NetworkID         string `json:"NetworkID"`
	IPAddress         string `json:"IPAddress"`
	GlobalIPv6Address string `json:"GlobalIPv6Address"`
	Gateway           string `json:"Gateway"`
	IPv6Gateway       string `json:"IPv6Gateway"`
}

type rawDockerNetworkSettings struct {
	Ports    map[string][]rawDockerPortBinding     `json:"Ports"`
	Networks map[string]rawDockerNetworkAttachment `json:"Networks"`
}

type rawDockerContainerInspection struct {
	ID           string   `json:"Id"`
	Name         string   `json:"Name"`
	Image        string   `json:"Image"`
	Created      string   `json:"Created"`
	Path         string   `json:"Path"`
	Args         []string `json:"Args"`
	Platform     string   `json:"Platform"`
	LogPath      string   `json:"LogPath"`
	RestartCount int      `json:"RestartCount"`
	State        *struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		Dead       bool   `json:"Dead"`
		PID        int    `json:"Pid"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status   string `json:"Status"`
			ExitCode int    `json:"ExitCode"`
		} `json:"Health"`
	} `json:"State"`
	Config *struct {
		Hostname     string              `json:"Hostname"`
		User         string              `json:"User"`
		WorkingDir   string              `json:"WorkingDir"`
		Image        string              `json:"Image"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		Env          []string            `json:"Env"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig *struct {
		NetworkMode    string `json:"NetworkMode"`
		Privileged     bool   `json:"Privileged"`
		ReadonlyRootfs bool   `json:"ReadonlyRootfs"`
		RestartPolicy  *struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
		RW          bool   `json:"RW"`
		Propagation string `json:"Propagation"`
	} `json:"Mounts"`
	NetworkSettings rawDockerNetworkSettings `json:"NetworkSettings"`
}

func parseDockerImageContainers(raw string) ([]dockerImageContainer, error) {
	entries := make([]dockerImageContainer, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var inspection rawDockerContainerInspection
		if err := json.Unmarshal([]byte(line), &inspection); err != nil {
			return nil, fmt.Errorf("cannot parse Docker container inspection: %w", err)
		}
		id := strings.TrimPrefix(strings.TrimSpace(inspection.ID), "sha256:")
		if !validDockerID(id) {
			return nil, errors.New("Docker container inspection returned an invalid container ID")
		}
		stateStatus := ""
		if inspection.State != nil {
			stateStatus = inspection.State.Status
		}
		entry := dockerImageContainer{
			ID:       id,
			Name:     strings.TrimPrefix(strings.TrimSpace(inspection.Name), "/"),
			Image:    strings.TrimSpace(inspection.Image),
			State:    strings.ToLower(strings.TrimSpace(stateStatus)),
			Status:   strings.TrimSpace(stateStatus),
			Ports:    parseDockerPortMappings(inspection.NetworkSettings),
			Networks: parseDockerNetworkAddresses(inspection.NetworkSettings),
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

func parseDockerPortMappings(settings rawDockerNetworkSettings) []dockerPortMapping {
	entries := make([]dockerPortMapping, 0)
	for containerPort, bindings := range settings.Ports {
		protocol := "tcp"
		if index := strings.LastIndex(containerPort, "/"); index >= 0 {
			protocol = strings.TrimSpace(containerPort[index+1:])
			containerPort = strings.TrimSpace(containerPort[:index])
		}
		for _, binding := range bindings {
			entries = append(entries, dockerPortMapping{
				ContainerPort: containerPort,
				HostIP:        strings.TrimSpace(binding.HostIP),
				HostPort:      strings.TrimSpace(binding.HostPort),
				Protocol:      protocol,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ContainerPort != entries[j].ContainerPort {
			return entries[i].ContainerPort < entries[j].ContainerPort
		}
		if entries[i].HostPort != entries[j].HostPort {
			return entries[i].HostPort < entries[j].HostPort
		}
		return entries[i].HostIP < entries[j].HostIP
	})
	return entries
}

func parseDockerNetworkAddresses(settings rawDockerNetworkSettings) []dockerNetworkAddress {
	entries := make([]dockerNetworkAddress, 0, len(settings.Networks))
	for network, attachment := range settings.Networks {
		entries = append(entries, dockerNetworkAddress{
			NetworkID:   strings.TrimSpace(attachment.NetworkID),
			Network:     strings.TrimSpace(network),
			IPAddress:   strings.TrimSpace(attachment.IPAddress),
			GlobalIPv6:  strings.TrimSpace(attachment.GlobalIPv6Address),
			Gateway:     strings.TrimSpace(attachment.Gateway),
			IPv6Gateway: strings.TrimSpace(attachment.IPv6Gateway),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Network < entries[j].Network
	})
	return entries
}

func parseDockerContainerDetailsBundle(raw string) (dockerContainerDetails, []string, error) {
	parts := strings.Split(raw, dockerContainerDetailsMarker)
	if len(parts) != 2 {
		return dockerContainerDetails{}, nil, errors.New("cannot parse Docker container details response")
	}
	details, err := parseDockerContainerInspection(parts[0])
	if err != nil {
		return dockerContainerDetails{}, nil, err
	}
	return details, strings.Fields(parts[1]), nil
}

func parseDockerContainerInspection(raw string) (dockerContainerDetails, error) {
	var inspection rawDockerContainerInspection
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &inspection); err != nil {
		return dockerContainerDetails{}, fmt.Errorf("cannot parse Docker container inspection: %w", err)
	}
	id := strings.TrimPrefix(strings.TrimSpace(inspection.ID), "sha256:")
	if !validDockerID(id) {
		return dockerContainerDetails{}, errors.New("Docker container inspection returned an invalid container ID")
	}
	imageID := strings.TrimPrefix(strings.TrimSpace(inspection.Image), "sha256:")
	if !validDockerID(imageID) {
		return dockerContainerDetails{}, errors.New("Docker container inspection returned an invalid image ID")
	}

	details := dockerContainerDetails{
		ID:           id,
		Name:         strings.TrimPrefix(strings.TrimSpace(inspection.Name), "/"),
		Image:        strings.TrimSpace(inspection.Image),
		ImageID:      imageID,
		Created:      strings.TrimSpace(inspection.Created),
		Path:         strings.TrimSpace(inspection.Path),
		Args:         nonEmptyStrings(inspection.Args),
		Platform:     strings.TrimSpace(inspection.Platform),
		LogPath:      strings.TrimSpace(inspection.LogPath),
		RestartCount: inspection.RestartCount,
		Labels:       map[string]string{},
		ExposedPorts: []string{},
		Ports:        parseDockerPortMappings(inspection.NetworkSettings),
		Networks:     parseDockerNetworkAddresses(inspection.NetworkSettings),
		HostIPs:      []string{},
		Mounts:       make([]dockerContainerMount, 0, len(inspection.Mounts)),
	}
	if inspection.Config != nil {
		if configuredImage := strings.TrimSpace(inspection.Config.Image); configuredImage != "" {
			details.Image = configuredImage
		}
		details.Hostname = strings.TrimSpace(inspection.Config.Hostname)
		details.User = strings.TrimSpace(inspection.Config.User)
		details.WorkingDir = strings.TrimSpace(inspection.Config.WorkingDir)
		details.Entrypoint = nonEmptyStrings(inspection.Config.Entrypoint)
		details.Cmd = nonEmptyStrings(inspection.Config.Cmd)
		details.Env = nonEmptyStrings(inspection.Config.Env)
		for key, value := range inspection.Config.Labels {
			details.Labels[key] = value
		}
		for port := range inspection.Config.ExposedPorts {
			port = strings.TrimSpace(port)
			if port != "" {
				details.ExposedPorts = append(details.ExposedPorts, port)
			}
		}
		sort.Strings(details.ExposedPorts)
	}
	if inspection.State != nil {
		details.State = dockerContainerState{
			Status:     strings.TrimSpace(inspection.State.Status),
			Running:    inspection.State.Running,
			Paused:     inspection.State.Paused,
			Restarting: inspection.State.Restarting,
			OOMKilled:  inspection.State.OOMKilled,
			Dead:       inspection.State.Dead,
			PID:        inspection.State.PID,
			ExitCode:   inspection.State.ExitCode,
			Error:      strings.TrimSpace(inspection.State.Error),
			StartedAt:  strings.TrimSpace(inspection.State.StartedAt),
			FinishedAt: strings.TrimSpace(inspection.State.FinishedAt),
		}
		if inspection.State.Health != nil {
			details.State.HealthStatus = strings.TrimSpace(inspection.State.Health.Status)
			details.State.HealthExitCode = inspection.State.Health.ExitCode
		}
	}
	if inspection.HostConfig != nil {
		details.NetworkMode = strings.TrimSpace(inspection.HostConfig.NetworkMode)
		details.Privileged = inspection.HostConfig.Privileged
		details.ReadonlyRootfs = inspection.HostConfig.ReadonlyRootfs
		if inspection.HostConfig.RestartPolicy != nil {
			details.RestartPolicy = strings.TrimSpace(inspection.HostConfig.RestartPolicy.Name)
		}
	}
	for _, mount := range inspection.Mounts {
		details.Mounts = append(details.Mounts, dockerContainerMount{
			Type:        strings.TrimSpace(mount.Type),
			Name:        strings.TrimSpace(mount.Name),
			Source:      strings.TrimSpace(mount.Source),
			Destination: strings.TrimSpace(mount.Destination),
			Mode:        strings.TrimSpace(mount.Mode),
			RW:          mount.RW,
			Propagation: strings.TrimSpace(mount.Propagation),
		})
	}
	sort.Slice(details.Mounts, func(i, j int) bool {
		return details.Mounts[i].Destination < details.Mounts[j].Destination
	})
	return details, nil
}

func nonEmptyStrings(values []string) []string {
	entries := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			entries = append(entries, value)
		}
	}
	return entries
}

func dockerCommandMessage(result commandResult) string {
	message := strings.TrimSpace(result.stderr)
	if message == "" {
		message = strings.TrimSpace(result.stdout)
	}
	if message == "" {
		message = fmt.Sprintf("Docker command failed with exit code %d", result.exitCode)
	}
	if dockerPermissionDenied(result) && !strings.Contains(strings.ToLower(message), "ssh user") {
		message += "\nThe Docker panel follows the SSH user's permissions. Add that user to the docker group, or connect as a user allowed to access the Docker socket; manually running su in the terminal does not change panel permissions."
	}
	return message
}

func dockerCommandError(result commandResult, operation string) map[string]any {
	if errors.Is(result.err, errRemoteCommandTimeout) {
		return dockerResultError(
			"Docker " + operation + " timed out; check the remote Docker daemon and SSH connection, then try again.",
		)
	}
	return dockerResultError(result.err.Error())
}

func dockerResultError(message string) map[string]any {
	return map[string]any{"success": false, "message": message}
}
