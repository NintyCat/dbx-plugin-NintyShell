package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

type sftpEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"isDir"`
	Size       int64  `json:"size,omitempty"`
	ModifiedAt string `json:"modifiedAt,omitempty"`
}

type uploadState struct {
	file  *sftp.File
	bytes int64
}

type uploadRegistry struct {
	mutex   sync.Mutex
	pending map[string]*uploadState
}

var uploads = &uploadRegistry{pending: map[string]*uploadState{}}

func (p *plugin) sftpList(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	path := resolveRemotePath(current, stringField(values, "path"))
	entries, err := client.ReadDir(path)
	if err != nil {
		return fail("Cannot list " + path + ": " + err.Error())
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	out := make([]sftpEntry, 0, len(entries))
	separator := ""
	if !strings.HasSuffix(path, "/") {
		separator = "/"
	}
	for _, entry := range entries {
		item := sftpEntry{
			Name:       entry.Name(),
			Path:       path + separator + entry.Name(),
			IsDir:      entry.IsDir(),
			ModifiedAt: entry.ModTime().UTC().Format(time.RFC3339),
		}
		if !entry.IsDir() {
			item.Size = entry.Size()
		}
		out = append(out, item)
	}
	return map[string]any{"path": path, "entries": out}, nil
}

func (p *plugin) sftpMkdir(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	path := resolveRemotePath(current, stringField(values, "path"))
	if path == "" || path == "/" {
		return fail("Invalid directory name")
	}
	if err := client.MkdirAll(path); err != nil {
		return fail("Cannot create directory: " + err.Error())
	}
	return map[string]any{"success": true, "path": path}, nil
}

func (p *plugin) sftpDelete(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	path := resolveRemotePath(current, stringField(values, "path"))
	if path == "" || path == "/" {
		return fail("Refusing to delete the root path")
	}
	recursive, _ := values["recursive"].(bool)
	info, statErr := client.Stat(path)
	if statErr != nil {
		return fail("Cannot stat " + path + ": " + statErr.Error())
	}
	if info.IsDir() && recursive {
		if err := removeRemoteTree(client, path); err != nil {
			return fail("Cannot delete directory: " + err.Error())
		}
	} else if info.IsDir() {
		if err := client.RemoveDirectory(path); err != nil {
			return fail("Cannot delete directory (use recursive for non-empty): " + err.Error())
		}
	} else {
		if err := client.Remove(path); err != nil {
			return fail("Cannot delete file: " + err.Error())
		}
	}
	return map[string]any{"success": true, "path": path}, nil
}

func removeRemoteTree(client *sftp.Client, path string) error {
	entries, err := client.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := path + "/" + entry.Name()
		if entry.IsDir() {
			if err := removeRemoteTree(client, child); err != nil {
				return err
			}
		} else if err := client.Remove(child); err != nil {
			return err
		}
	}
	return client.RemoveDirectory(path)
}

func (p *plugin) sftpRename(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	from := resolveRemotePath(current, stringField(values, "from"))
	to := resolveRemotePath(current, stringField(values, "to"))
	if from == "" || to == "" || from == "/" || to == "/" {
		return fail("Invalid rename paths")
	}
	if err := client.PosixRename(from, to); err != nil {
		return fail("Cannot rename: " + err.Error())
	}
	return map[string]any{"success": true, "path": to}, nil
}

func (p *plugin) sftpUploadBegin(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	path := resolveRemotePath(current, stringField(values, "path"))
	if path == "" || strings.HasSuffix(path, "/") {
		return fail("Invalid upload path")
	}
	file, err := client.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fail("Cannot open remote file: " + err.Error())
	}
	id := newUploadID()
	uploads.mutex.Lock()
	uploads.pending[id] = &uploadState{file: file}
	uploads.mutex.Unlock()
	return map[string]any{"success": true, "uploadId": id, "path": path}, nil
}

func (p *plugin) sftpUploadChunk(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	upload, ok := peekUpload(stringField(values, "uploadId"))
	if !ok {
		return nil, dbxpluginsdk.NewError(-32602, "Unknown uploadId")
	}
	data, err := base64.StdEncoding.DecodeString(stringField(values, "data"))
	if err != nil {
		upload.file.Close()
		dropUpload(stringField(values, "uploadId"))
		return fail("Invalid upload chunk encoding")
	}
	if _, err := upload.file.Write(data); err != nil {
		upload.file.Close()
		return fail("Upload write failed: " + err.Error())
	}
	upload.bytes += int64(len(data))
	return map[string]any{"success": true, "received": upload.bytes}, nil
}

func (p *plugin) sftpUploadEnd(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	upload, ok := popUpload(stringField(values, "uploadId"))
	if !ok {
		return nil, dbxpluginsdk.NewError(-32602, "Unknown uploadId")
	}
	if err := upload.file.Close(); err != nil {
		return fail("Upload close failed: " + err.Error())
	}
	return map[string]any{"success": true, "size": upload.bytes}, nil
}

// sftpDownload copies a remote file to a local directory (the sidecar runs on
// the user's machine, defaulting to ~/Downloads).
func (p *plugin) sftpDownload(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	current, pluginErr := p.sessionFor(values)
	if pluginErr != nil {
		return nil, pluginErr
	}
	client, err := current.sftpClient()
	if err != nil {
		return fail(err.Error())
	}
	path := resolveRemotePath(current, stringField(values, "path"))
	if path == "" || strings.HasSuffix(path, "/") {
		return fail("Invalid download path")
	}
	remote, err := client.Open(path)
	if err != nil {
		return fail("Cannot open remote file: " + err.Error())
	}
	defer remote.Close()
	info, err := remote.Stat()
	if err != nil {
		return fail("Cannot stat remote file: " + err.Error())
	}
	if info.IsDir() {
		return fail("Cannot download a directory")
	}
	localDir := stringField(values, "localDir")
	if pick, _ := values["pickDir"].(bool); pick {
		// The user picks the destination in a native folder chooser; a
		// cancelled dialog aborts the download without an error.
		chosen, ok := pickDownloadDir()
		if !ok {
			return map[string]any{"success": true, "cancelled": true}, nil
		}
		localDir = chosen
	}
	if expanded, ok := expandHome(localDir); ok {
		localDir = expanded
	}
	if strings.TrimSpace(localDir) == "" {
		home, _ := os.UserHomeDir()
		localDir = filepath.Join(home, "Downloads")
	}
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return fail("Cannot create local directory: " + err.Error())
	}
	localPath := filepath.Join(localDir, filepath.Base(path))
	local, err := os.Create(localPath)
	if err != nil {
		return fail("Cannot create local file: " + err.Error())
	}
	defer local.Close()
	written, err := io.Copy(local, remote)
	if err != nil {
		return fail("Download failed: " + err.Error())
	}
	return map[string]any{
		"success":   true,
		"localPath": localPath,
		"size":      written,
	}, nil
}

func peekUpload(id string) (*uploadState, bool) {
	if id == "" {
		return nil, false
	}
	uploads.mutex.Lock()
	defer uploads.mutex.Unlock()
	state, ok := uploads.pending[id]
	return state, ok
}

func dropUpload(id string) {
	if id == "" {
		return
	}
	uploads.mutex.Lock()
	defer uploads.mutex.Unlock()
	delete(uploads.pending, id)
}

func popUpload(id string) (*uploadState, bool) {
	if id == "" {
		return nil, false
	}
	uploads.mutex.Lock()
	defer uploads.mutex.Unlock()
	state, ok := uploads.pending[id]
	if ok {
		delete(uploads.pending, id)
	}
	return state, ok
}

func newUploadID() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

func stringField(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}
