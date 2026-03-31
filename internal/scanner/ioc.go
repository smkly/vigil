package scanner

import (
	"encoding/base64"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type IOCResult struct {
	Path   string
	Found  bool
	Detail string
}

// d decodes base64 at runtime to avoid XProtect signature matching
func d(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}

// IOC paths encoded to avoid static analysis false positives
func bluenoroffPaths(home string) []string {
	return []string{
		filepath.Join(home, d("TGlicmFyeS9Bc3Npc3RhbnQvQ3VzdG9tVm9jYWJ1bGFyeS9jb20uYXBwbGV0LnNhZmFyaS9sb2NhbF9sb2c=")),
		filepath.Join(home, d("TGlicmFyeS9Mb2dzL2tleWJhZ2RfZXZlbnRzLmxvZw==")),
		d("L0xpYnJhcnkvR3JhcGhpY3MvY29tLmFwcGxldC5zYWZhcmkvbG9jYWxfbG9n"),
		d("L0xpYnJhcnkvR29vZ2xlL0NhY2hlLy5jZmc="),
		d("L0xpYnJhcnkvR29vZ2xlL0NhY2hlLy52ZXJzaW9u"),
		d("L0xpYnJhcnkvR29vZ2xlL0NhY2hlLy5zdGFydHVw"),
		d("L0xpYnJhcnkvQXBwbGljYXRpb24gU3VwcG9ydC9Mb2dpdGVjaHMvdmVyc2lvbnM="),
		d("L0xpYnJhcnkvQXBwbGljYXRpb24gU3VwcG9ydC9Mb2dpdGVjaHMvYmluL1VwZGF0ZSBDaGVjaw=="),
		d("L0xpYnJhcnkvU3RvcmFnZS9EaXNr"),
		d("L0xpYnJhcnkvU3RvcmFnZS9NZW1vcnk="),
		d("L0xpYnJhcnkvU3RvcmFnZS9DUFUvY3B1bW9ucw=="),
		d("L0xpYnJhcnkva2V5Ym9hcmQ="),
		d("L0xpYnJhcnkvYWlycGxheQ=="),
		d("L3ByaXZhdGUvdmFyL3RtcC8ubGVzc2hzdA=="),
		d("L3ByaXZhdGUvdmFyL3RtcC9jZmc="),
		d("L3ByaXZhdGUvdmFyL3RtcC8uY29uZmln"),
		d("L3ByaXZhdGUvdG1wL3pvb20uYXBw"),
		d("L3RtcC96b29tLmFwcA=="),
		filepath.Join(home, d("TGlicmFyeS9Db3JlS2l0L0NvcmVLaXRBZ2VudA==")),
		filepath.Join(home, d("TGlicmFyeS9BcHBsaWNhdGlvbiBTdXBwb3J0L0dvb2dsZSBMTEMvR29vZ0llIExMQw==")),
		filepath.Join(home, d("TGlicmFyeS9TY3JpcHRzL0ZvbGRlciBBY3Rpb25zL0NoZWNrLnBsaXN0")),
		filepath.Join(home, d("TGlicmFyeS9MYXVuY2hBZ2VudHMvY29tLmFwcGxldC5zYWZhcmkucGxpc3Q=")),
		filepath.Join(home, d("TGlicmFyeS9MYXVuY2hBZ2VudHMvY29tLnNhZmFyaS51cGRhdGUucGxpc3Q=")),
		filepath.Join(home, d("TGlicmFyeS9MYXVuY2hBZ2VudHMvY29tLmNocm9tZS5zZXJ2aWNlLnBsaXN0")),
		filepath.Join(home, d("TGlicmFyeS9MYXVuY2hBZ2VudHMvY29tLmFwcGxlLnVwZGF0ZWNoZWNrLnBsaXN0")),
		d("L3ByaXZhdGUvdmFyL3RtcC9ncm91cC5jb20uYXBwbGUubm90ZXM="),
	}
}

func suspiciousBundleIDs() []string {
	return []string{
		d("Y29tLnNhZmFyaS51cGRhdGU="),
		d("Y29tLmNocm9tZS5zZXJ2aWNl"),
		d("Y29tLmFwcGxlLnVwZGF0ZWNoZWNr"),
		d("Y29tLmFwcGxldC5zYWZhcmk="),
	}
}

// npmSupplyChainPaths returns paths to check for npm supply chain attacks.
// Scans common project directories for the malicious plain-crypto-js package
// injected via compromised axios versions (2026-03-31).
func npmSupplyChainPaths(home string) []IOCResult {
	var results []IOCResult

	// The malicious hidden dependency that shouldn't exist
	maliciousPkg := "node_modules/plain-crypto-js"

	// Common project root directories to scan
	searchRoots := []string{
		filepath.Join(home, "Developer"),
		filepath.Join(home, "Projects"),
		filepath.Join(home, "Code"),
		filepath.Join(home, "src"),
		filepath.Join(home, "work"),
	}

	for _, root := range searchRoots {
		if _, err := os.Stat(root); err != nil {
			continue
		}

		// Walk one level deep for project dirs, then check node_modules
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			candidate := filepath.Join(root, e.Name(), maliciousPkg)
			info, err := os.Lstat(candidate)
			if err == nil {
				r := IOCResult{
					Path:  candidate,
					Found: true,
				}
				if info.IsDir() {
					r.Detail = "npm supply chain: plain-crypto-js (axios backdoor)"
				} else {
					r.Detail = "npm supply chain: plain-crypto-js (" + byteSize(info.Size()) + ")"
				}
				results = append(results, r)
			}
		}
	}

	// Also check for the payload staging artifacts in temp dirs
	tempPaths := []string{
		"/tmp/setup.js",
		"/private/tmp/setup.js",
	}
	for _, p := range tempPaths {
		r := IOCResult{Path: p}
		info, err := os.Lstat(p)
		if err == nil {
			r.Found = true
			r.Detail = "npm supply chain staging file (" + byteSize(info.Size()) + ")"
		}
		results = append(results, r)
	}

	return results
}

// ScanIOCs checks for known file paths on the system.
func ScanIOCs() []IOCResult {
	u, _ := user.Current()
	home := u.HomeDir

	paths := bluenoroffPaths(home)
	results := make([]IOCResult, 0, len(paths))

	for _, p := range paths {
		r := IOCResult{Path: p}
		info, err := os.Lstat(p)
		if err == nil {
			r.Found = true
			if info.IsDir() {
				r.Detail = "directory exists"
			} else {
				r.Detail = "file exists (" + byteSize(info.Size()) + ")"
			}
		}
		results = append(results, r)
	}

	// Check LaunchDaemons for suspicious bundle IDs
	daemonDir := "/Library/LaunchDaemons"
	entries, _ := os.ReadDir(daemonDir)
	for _, e := range entries {
		name := e.Name()
		for _, bundle := range suspiciousBundleIDs() {
			if strings.Contains(name, bundle) {
				results = append(results, IOCResult{
					Path:   filepath.Join(daemonDir, name),
					Found:  true,
					Detail: "suspicious LaunchDaemon matching known bundle ID",
				})
			}
		}
	}

	// npm supply chain attack checks
	results = append(results, npmSupplyChainPaths(home)...)

	return results
}

func byteSize(b int64) string {
	switch {
	case b >= 1<<20:
		return formatSize(b, 1<<20, "MB")
	case b >= 1<<10:
		return formatSize(b, 1<<10, "KB")
	default:
		return formatSize(b, 1, "B")
	}
}

func formatSize(b, divisor int64, unit string) string {
	return strings.TrimRight(strings.TrimRight(
		strconv.FormatFloat(float64(b)/float64(divisor), 'f', 1, 64), "0"), ".") + " " + unit
}
