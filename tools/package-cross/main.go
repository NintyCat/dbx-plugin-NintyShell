// Command package-cross builds the DBX plugin .dbxp for any target platform.
//
// The official `dbx-plugin package` command refuses to cross-compile
// ("Native plugin target ... does not match build host; run this package
// command on the target platform"), so this tool reproduces its output for
// other targets. It builds the Go backend with CGO_ENABLED=0 so the sidecar
// is a pure-Go static binary that does not depend on the host glibc version
// (avoids "libc.so.6: version GLIBC_2.34 not found" on older distros),
// stages the directories listed in dbx-plugin.toml, rewrites the backend
// executable path in manifest.json, and writes
// <id>-<version>-<target>.dbxp plus the matching .artifact.json.
//
// Usage (from the repository root):
//
//	go -C tools/package-cross run . -target linux-x64
//
// Targets: linux-x64, linux-arm64, windows-x64, windows-arm64,
// darwin-x64, darwin-arm64.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type targetSpec struct{ goos, goarch string }

var knownTargets = map[string]targetSpec{
	"linux-x64":     {"linux", "amd64"},
	"linux-arm64":   {"linux", "arm64"},
	"windows-x64":   {"windows", "amd64"},
	"windows-arm64": {"windows", "arm64"},
	"darwin-x64":    {"darwin", "amd64"},
	"darwin-arm64":  {"darwin", "arm64"},
}

const checksumsName = "checksums.json"

func main() {
	target := flag.String("target", "", "package target (e.g. linux-x64)")
	out := flag.String("out", "dist", "output directory, relative to the repository root")
	flag.Parse()

	spec, ok := knownTargets[*target]
	if !ok {
		var names []string
		for name := range knownTargets {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "usage: package-cross -target <%s>\n", strings.Join(names, "|"))
		os.Exit(2)
	}

	root, err := findRoot()
	check(err, "locate repository root (manifest.json + dbx-plugin.toml)")

	binary, include, err := parseCfg(filepath.Join(root, "dbx-plugin.toml"))
	check(err, "read dbx-plugin.toml")

	manifestPath := filepath.Join(root, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	check(err, "read manifest.json")

	var identity struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	check(json.Unmarshal(manifestRaw, &identity), "parse manifest.json identity")
	if identity.ID == "" || identity.Version == "" {
		check(errors.New("id or version is empty"), "parse manifest.json identity")
	}

	files := map[string][]byte{}

	// Stage the include directories (same set dbx-plugin.toml declares).
	for _, inc := range include {
		base := filepath.Join(root, inc)
		if _, err := os.Stat(base); err != nil {
			check(fmt.Errorf("package include %q does not exist", inc), "stage includes")
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = data
			return nil
		})
		check(err, "stage includes")
	}

	// Rewrite the backend executable path for this target (dbx-plugin does
	// the same when it packages natively).
	execRe := regexp.MustCompile(`"executable"\s*:\s*"bin/[^"]*"`)
	match := execRe.FindIndex(manifestRaw)
	if match == nil || len(execRe.FindAllIndex(manifestRaw, -1)) != 1 {
		check(errors.New("expected exactly 1 backend executable entry in manifest.json"), "rewrite manifest.json")
	}
	binName := binary
	if spec.goos == "windows" {
		binName += ".exe"
	}
	rewritten := fmt.Sprintf(`"executable": "bin/%s/%s"`, *target, binName)
	manifestRaw = concat(manifestRaw[:match[0]], []byte(rewritten), manifestRaw[match[1]:])
	files["manifest.json"] = manifestRaw

	// Cross-build the sidecar: pure Go, statically linked.
	backendData, err := buildBackend(root, spec)
	check(err, "build Go backend")
	if spec.goos == "linux" {
		check(verifyStatic(backendData), "verify static backend")
	}
	files["bin/"+*target+"/"+binName] = backendData

	// checksums.json covers every staged file (not itself), sha256, sorted keys.
	checksums := struct {
		Algorithm string            `json:"algorithm"`
		Files     map[string]string `json:"files"`
	}{Algorithm: "sha256", Files: map[string]string{}}
	for name, data := range files {
		sum := sha256.Sum256(data)
		checksums.Files[name] = hex.EncodeToString(sum[:])
	}
	checksumsJSON, err := json.MarshalIndent(checksums, "", "  ")
	check(err, "encode checksums.json")
	files[checksumsName] = append(checksumsJSON, '\n')

	// Write the package: sorted entries, checksums.json last (CLI layout).
	if !filepath.IsAbs(*out) {
		*out = filepath.Join(root, *out)
	}
	check(os.MkdirAll(*out, 0o755), "create output directory")
	pkgName := fmt.Sprintf("%s-%s-%s.dbxp", identity.ID, identity.Version, *target)
	pkgPath := filepath.Join(*out, pkgName)
	pkgData, err := writePackage(pkgPath, files)
	check(err, "write package")

	sum := sha256.Sum256(pkgData)
	artifact := struct {
		Target string `json:"target"`
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}{Target: *target, URL: pkgName, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(pkgData))}
	artifactJSON, err := json.MarshalIndent(artifact, "", "  ")
	check(err, "encode artifact metadata")
	artifactBase := strings.TrimSuffix(pkgName, ".dbxp")
	check(os.WriteFile(filepath.Join(*out, artifactBase+".artifact.json"), append(artifactJSON, '\n'), 0o644), "write artifact metadata")

	fmt.Printf("Built %s\n", pkgPath)
	fmt.Printf("Backend: %d bytes, CGO_ENABLED=0, statically linked (no glibc dependency)\n", len(backendData))
	fmt.Printf("sha256: %s\n", artifact.SHA256)
	fmt.Printf("Signature: unsigned review candidate\n")
}

func check(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", what, err)
		os.Exit(1)
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// findRoot walks upward until it finds the plugin repository root.
func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(dir, "manifest.json")) && fileExists(filepath.Join(dir, "dbx-plugin.toml")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no parent directory contains manifest.json + dbx-plugin.toml")
		}
		dir = parent
	}
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func parseCfg(path string) (binary string, include []string, _ error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	if m := regexp.MustCompile(`(?m)^\s*binary\s*=\s*"([^"]+)"`).FindSubmatch(data); m != nil {
		binary = string(m[1])
	}
	if binary == "" {
		return "", nil, errors.New("backend.binary is not set")
	}
	if m := regexp.MustCompile(`(?m)^\s*include\s*=\s*\[([^\]]*)\]`).FindSubmatch(data); m != nil {
		for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(string(m[1]), -1) {
			include = append(include, q[1])
		}
	}
	if len(include) == 0 {
		include = []string{"assets", "ui"}
	}
	return binary, include, nil
}

func buildBackend(root string, spec targetSpec) ([]byte, error) {
	tmp, err := os.CreateTemp("", "nintyshell-build-*")
	if err != nil {
		return nil, err
	}
	out := tmp.Name()
	tmp.Close()
	os.Remove(out)
	defer os.Remove(out)

	cmd := exec.Command("go", "build", "-trimpath", "-o", out, ".")
	cmd.Dir = filepath.Join(root, "backend")
	// Last occurrence wins in os/exec, so these override any inherited values.
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+spec.goos,
		"GOARCH="+spec.goarch,
		"GOWORK=off",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w\n%s", err, output)
	}
	return os.ReadFile(out)
}

// verifyStatic rejects a backend that would need a system libc at runtime.
func verifyStatic(data []byte) error {
	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parse ELF: %w", err)
	}
	for _, prog := range elfFile.Progs {
		switch prog.Type {
		case elf.PT_INTERP:
			return errors.New("binary needs a dynamic loader (PT_INTERP); CGO_ENABLED=0 missing?")
		case elf.PT_DYNAMIC:
			return errors.New("binary has a dynamic section (PT_DYNAMIC); CGO_ENABLED=0 missing?")
		}
	}
	if bytes.Contains(data, []byte("GLIBC_")) {
		return errors.New("binary references GLIBC_ symbols")
	}
	return nil
}

// writePackage writes the zip and returns its bytes. Entry layout matches the
// official CLI: sorted files, checksums.json last, Unix modes 0755 for the
// manifest and the backend, 0644 for everything else.
func writePackage(path string, files map[string][]byte) ([]byte, error) {
	var names []string
	for name := range files {
		if name == checksumsName {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	names = append(names, checksumsName)

	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	zw := zip.NewWriter(f)
	now := time.Now()
	for _, name := range names {
		mode := fs.FileMode(0o644)
		if name == "manifest.json" || strings.HasPrefix(name, "bin/") {
			mode = 0o755
		}
		fh := &zip.FileHeader{Name: name, Method: zip.Deflate, CreatorVersion: 20}
		fh.Modified = now
		fh.SetMode(mode)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			f.Close()
			return nil, err
		}
		if _, err := w.Write(files[name]); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
