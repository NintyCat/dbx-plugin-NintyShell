package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Sidecar 初始化响应里的 id/version 必须与包根 manifest.json 完全一致，
// 否则宿主拒绝初始化插件（"backend identity does not match manifest"）。
func TestMetadataMatchesManifest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var manifest struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest.json: %v", err)
	}
	if manifest.ID != pluginID {
		t.Errorf("manifest id %q != sidecar id %q", manifest.ID, pluginID)
	}
	if manifest.Version != pluginVersion {
		t.Errorf("manifest version %q != sidecar version %q（改版本时需同步 manifest.json 与 main.go）", manifest.Version, pluginVersion)
	}
}
