package scanner

import (
	"encoding/base64"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

type LaunchItem struct {
	Path       string
	Name       string
	Location   string
	Suspicious bool
	Reason     string
}

var applePrefixes = []string{
	"com.apple.",
	"com.microsoft.",
	"com.google.",
}

func dec(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}

func suspiciousPatterns() []string {
	return []string{
		dec("Y29tLmFwcGxldC4="),
		dec("Y29tLnNhZmFyaS51cGRhdGU="),
		dec("Y29tLmNocm9tZS5zZXJ2aWNl"),
		dec("Y29tLmFwcGxlLnVwZGF0ZWNoZWNr"),
	}
}

func ScanLaunchItems() []LaunchItem {
	u, _ := user.Current()
	home := u.HomeDir

	dirs := []struct {
		path     string
		location string
	}{
		{filepath.Join(home, "Library/LaunchAgents"), "User LaunchAgents"},
		{"/Library/LaunchAgents", "System LaunchAgents"},
		{"/Library/LaunchDaemons", "LaunchDaemons"},
	}

	var items []LaunchItem

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			item := LaunchItem{
				Path:     filepath.Join(dir.path, e.Name()),
				Name:     e.Name(),
				Location: dir.location,
			}

			for _, pattern := range suspiciousPatterns() {
				if strings.Contains(e.Name(), pattern) {
					item.Suspicious = true
					item.Reason = "matches known threat bundle ID pattern"
					break
				}
			}

			if !item.Suspicious {
				isKnown := false
				for _, prefix := range applePrefixes {
					if strings.HasPrefix(e.Name(), prefix) {
						isKnown = true
						break
					}
				}
				if !isKnown {
					item.Reason = "third-party"
				}
			}

			items = append(items, item)
		}
	}

	return items
}
