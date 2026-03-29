package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type TrustedList struct {
	Processes    []string `json:"processes"`
	LaunchItems  []string `json:"launch_items"`
	mu           sync.RWMutex
	path         string
}

var trustedInstance *TrustedList

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vigil")
}

func trustedPath() string {
	return filepath.Join(configDir(), "trusted.json")
}

func LoadTrusted() *TrustedList {
	if trustedInstance != nil {
		return trustedInstance
	}

	t := &TrustedList{path: trustedPath()}

	data, err := os.ReadFile(t.path)
	if err == nil {
		json.Unmarshal(data, t)
	}

	trustedInstance = t
	return t
}

func (t *TrustedList) Save() error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(t.path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(t.path, data, 0600)
}

func (t *TrustedList) TrustProcess(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, p := range t.Processes {
		if p == name {
			return
		}
	}
	t.Processes = append(t.Processes, name)
}

func (t *TrustedList) UntrustProcess(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for i, p := range t.Processes {
		if p == name {
			t.Processes = append(t.Processes[:i], t.Processes[i+1:]...)
			return
		}
	}
}

func (t *TrustedList) TrustLaunchItem(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, l := range t.LaunchItems {
		if l == name {
			return
		}
	}
	t.LaunchItems = append(t.LaunchItems, name)
}

func (t *TrustedList) UntrustLaunchItem(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for i, l := range t.LaunchItems {
		if l == name {
			t.LaunchItems = append(t.LaunchItems[:i], t.LaunchItems[i+1:]...)
			return
		}
	}
}

func (t *TrustedList) IsProcessTrusted(name string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, p := range t.Processes {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}

func (t *TrustedList) IsLaunchItemTrusted(name string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, l := range t.LaunchItems {
		if strings.EqualFold(name, l) {
			return true
		}
	}
	return false
}

// IsFirstRun returns true if no trusted.json exists yet
func IsFirstRun() bool {
	_, err := os.Stat(trustedPath())
	return os.IsNotExist(err)
}

// BaselineProcesses scans current network processes and returns unique names
func BaselineProcesses() []string {
	conns := ScanConnections()
	seen := make(map[string]bool)
	var procs []string
	for _, c := range conns {
		if c.Process != "" && !seen[c.Process] {
			seen[c.Process] = true
			procs = append(procs, c.Process)
		}
	}
	return procs
}

// BaselineLaunchItems scans current launch items and returns names
func BaselineLaunchItems() []string {
	items := ScanLaunchItems()
	var names []string
	for _, item := range items {
		if !item.Suspicious {
			names = append(names, item.Name)
		}
	}
	return names
}

// TrustBaseline trusts all provided processes and launch items
func (t *TrustedList) TrustBaseline(procs []string, launchItems []string) {
	for _, p := range procs {
		t.TrustProcess(p)
	}
	for _, l := range launchItems {
		t.TrustLaunchItem(l)
	}
}
