package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

const fsScheme = "sftp://"

const (
	writeExisting        = os.O_WRONLY
	writeCreateTrunc     = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	writeCreateExclusive = os.O_WRONLY | os.O_CREATE | os.O_EXCL
)

// fsTarget resolves the session and absolute remote path behind an sftp:// URI.
// connectionId is optional in filesystem RPCs: with one live session it is used
// implicitly, otherwise the caller must identify the connection.
func (p *plugin) fsTarget(values map[string]any, uriKey string) (*shellSession, string, *dbxpluginsdk.PluginError) {
	sessionID := requestSessionID(values)
	p.mutex.Lock()
	var current *shellSession
	if sessionID != "" {
		current = p.sessions[sessionID]
	} else if len(p.sessions) == 1 {
		for _, only := range p.sessions {
			current = only
		}
	}
	p.mutex.Unlock()
	if current == nil {
		return nil, "", dbxpluginsdk.NewError(-32000, "Session is not connected")
	}
	uri, _ := values[uriKey].(string)
	if uri == "" {
		return nil, "", dbxpluginsdk.NewError(-32602, "Missing "+uriKey)
	}
	if !strings.HasPrefix(uri, fsScheme) {
		return nil, "", dbxpluginsdk.NewError(-32602, "URI scheme must be sftp://")
	}
	remote := strings.TrimPrefix(uri, fsScheme)
	remote = resolveRemotePath(current, remote)
	return current, remote, nil
}

func fsURI(remotePath string) string {
	return fsScheme + remotePath
}

type fsEntry struct {
	Name       string `json:"name"`
	URI        string `json:"uri"`
	Kind       string `json:"kind"`
	Size       int64  `json:"size,omitempty"`
	ModifiedAt string `json:"modifiedAt,omitempty"`
}

func (p *plugin) fsList(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, remote, pluginErr := p.fsTarget(values, "uri")
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	entries, err := client.ReadDir(remote)
	if err != nil {
		return fail("Cannot list " + remote + ": " + err.Error())
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	limit := fsLimit(values)
	skip := fsCursor(values)
	total := len(entries)
	if skip >= total {
		return map[string]any{"entries": []any{}}, nil
	}
	entries = entries[skip:]
	truncated := false
	if len(entries) > limit {
		entries = entries[:limit]
		truncated = true
	}
	out := make([]fsEntry, 0, len(entries))
	separator := ""
	if !strings.HasSuffix(remote, "/") {
		separator = "/"
	}
	for _, entry := range entries {
		item := fsEntry{
			Name:       entry.Name(),
			URI:        fsURI(remote + separator + entry.Name()),
			Kind:       "file",
			ModifiedAt: entry.ModTime().UTC().Format(time.RFC3339),
		}
		if entry.IsDir() {
			item.Kind = "directory"
		} else if entry.Mode().Type()&os.ModeSymlink != 0 {
			item.Kind = "symlink"
			if info, err := client.Stat(remote + separator + entry.Name()); err == nil && info.IsDir() {
				item.Kind = "directory"
			}
		} else {
			item.Size = entry.Size()
		}
		out = append(out, item)
	}
	result := map[string]any{"entries": out}
	if truncated {
		result["nextCursor"] = fmt.Sprintf("skip:%d", skip+len(out))
	}
	return result, nil
}

func (p *plugin) fsRead(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, remote, pluginErr := p.fsTarget(values, "uri")
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	maxBytes := int64(4 * 1024 * 1024)
	if v, ok := values["maxBytes"].(float64); ok && v > 0 {
		maxBytes = int64(v)
	}
	file, err := client.Open(remote)
	if err != nil {
		return fail("Cannot open " + remote + ": " + err.Error())
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fail("Cannot stat " + remote + ": " + err.Error())
	}
	if info.IsDir() {
		return fail("Cannot read a directory")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		return fail("Cannot read " + remote + ": " + err.Error())
	}
	return map[string]any{
		"dataBase64": base64.StdEncoding.EncodeToString(data),
		"truncated":  info.Size() > int64(len(data)),
	}, nil
}

func (p *plugin) fsWrite(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, remote, pluginErr := p.fsTarget(values, "uri")
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	create, _ := values["create"].(bool)
	overwrite, _ := values["overwrite"].(bool)
	flags := 0
	switch {
	case create && overwrite:
		flags = writeCreateTrunc
	case create:
		flags = writeCreateExclusive
	default:
		flags = writeExisting
	}
	data, err := base64.StdEncoding.DecodeString(stringField(values, "dataBase64"))
	if err != nil {
		return fail("Invalid write payload encoding")
	}
	file, err := client.OpenFile(remote, flags)
	if err != nil {
		return fail("Cannot open " + remote + ": " + err.Error())
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return fail("Write failed: " + err.Error())
	}
	return map[string]any{"success": true, "message": fmt.Sprintf("Wrote %d bytes to %s", len(data), remote)}, nil
}

func (p *plugin) fsCreateDirectory(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, remote, pluginErr := p.fsTarget(values, "uri")
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	if remote == "" || remote == "/" {
		return fail("Invalid directory path")
	}
	if err := client.Mkdir(remote); err != nil {
		return fail("Cannot create directory: " + err.Error())
	}
	return map[string]any{"success": true, "message": "Created " + remote}, nil
}

func (p *plugin) fsDelete(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, remote, pluginErr := p.fsTarget(values, "uri")
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	if remote == "" || remote == "/" {
		return fail("Refusing to delete the root path")
	}
	recursive, _ := values["recursive"].(bool)
	info, statErr := client.Stat(remote)
	if statErr != nil {
		return fail("Cannot stat " + remote + ": " + statErr.Error())
	}
	if info.IsDir() && recursive {
		if err := removeRemoteTree(client, remote); err != nil {
			return fail("Cannot delete directory: " + err.Error())
		}
	} else if info.IsDir() {
		if err := client.RemoveDirectory(remote); err != nil {
			return fail("Cannot delete directory: " + err.Error())
		}
	} else if err := client.Remove(remote); err != nil {
		return fail("Cannot delete file: " + err.Error())
	}
	return map[string]any{"success": true, "message": "Deleted " + remote}, nil
}

func (p *plugin) fsRename(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, source, pluginErr := p.fsTarget(values, "sourceUri")
	if pluginErr != nil {
		return nil, pluginErr
	}
	target := ""
	targetURI, _ := values["targetUri"].(string)
	if !strings.HasPrefix(targetURI, fsScheme) {
		return nil, dbxpluginsdk.NewError(-32602, "URI scheme must be sftp://")
	}
	target = resolveRemotePath(current, strings.TrimPrefix(targetURI, fsScheme))
	if source == "" || target == "" || source == "/" || target == "/" {
		return fail("Invalid rename paths")
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	if err := client.PosixRename(source, target); err != nil {
		return fail("Cannot rename: " + err.Error())
	}
	return map[string]any{"success": true, "message": "Renamed to " + path.Base(target)}, nil
}

func fsLimit(values map[string]any) int {
	if v, ok := values["limit"].(float64); ok && v > 0 {
		if int(v) > sftpListLimit {
			return sftpListLimit
		}
		return int(v)
	}
	return 100
}

func fsCursor(values map[string]any) int {
	cursor, _ := values["cursor"].(string)
	cursor = strings.TrimPrefix(cursor, "skip:")
	skip := 0
	for _, ch := range cursor {
		if ch < '0' || ch > '9' {
			return 0
		}
		skip = skip*10 + int(ch-'0')
	}
	return skip
}
