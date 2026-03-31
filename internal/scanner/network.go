package scanner

import (
	"encoding/base64"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

type Connection struct {
	Process    string
	PID        string
	Protocol   string
	LocalAddr  string
	LocalPort  string
	RemoteAddr string
	RemoteHost string
	RemotePort string
	State      string
	Risk       RiskLevel
	Reason     string
	FirstSeen  time.Time
	Count      int // number of connections grouped together
}

type RiskLevel int

const (
	RiskNone    RiskLevel = iota
	RiskLow               // known safe processes
	RiskMedium            // unknown process or unusual port
	RiskHigh              // matches C2 or suspicious pattern
)

func (r RiskLevel) String() string {
	switch r {
	case RiskHigh:
		return "HIGH"
	case RiskMedium:
		return "MEDIUM"
	case RiskLow:
		return "LOW"
	default:
		return "OK"
	}
}

func b64(s string) string {
	d, _ := base64.StdEncoding.DecodeString(s)
	return string(d)
}

func knownC2() []string {
	return []string{
		// BlueNoroff
		b64("ZmlsZS1zZXJ2ZXIuc3RvcmU="),
		b64("Y2xvdWQtc2VydmVyLnN0b3Jl"),
		b64("Zmxhc2hzZXJ2ZS5zdG9yZQ=="),
		b64("Y2hrYWN0aXZlLm9ubGluZQ=="),
		// npm supply chain (axios/plain-crypto-js, 2026-03-31)
		b64("c2ZyY2xhay5jb20="), // sfrclak.com
	}
}

func suspiciousProcs() map[string]string {
	return map[string]string{
		b64("d2F0Y2hkb2c="):         "known dropper launcher",
		b64("Q29yZUtpdEFnZW50"):     "known dropper",
		b64("Y3B1bW9ucw=="):         "known persistence binary",
		b64("a2V5Ym9hcmRk"):         "known keylogger",
		b64("YWlybW9uZA=="):         "known infostealer",
		b64("Q2hyb21lVXBkYXRlcw=="): "known baseApp",
		b64("VXBkYXRlIENoZWNr"):     "known component",
		b64("cnR2NGluc3Q="):         "known installer",
		b64("R29vZ0llIExMQw=="):     "known loader",
	}
}

// Processes / prefixes that are known safe
var knownSafePrefixes = []string{
	"Google",
	"Chrome",
	"Safari",
	"firefox",
	"Slack",
	"Spotify",
	"Code",
	"Electron",
	"node",
	"com.apple.",
	"com.google.",
	"nsurlsession",
	"mDNSResponder",
	"apsd",
	"cloudd",
	"identityservi",
	"IMDPersistenc",
	"parsecd",
	"rapportd",
	"sharingd",
	"WiFiAgent",
	"SystemUIServe",
	"networkservic",
	"WindowServer",
	"loginwindow",
	"UserEventAgen",
	"NotificationC",
	"distnoted",
	"cfprefsd",
	"trustd",
	"lsd",
	"secd",
	"Finder",
	"Dock",
	"Terminal",
	"iTerm",
	"Alacritty",
	"WezTerm",
	"kitty",
	"tmux",
	"ssh",
	"sshd",
	"curl",
	"git",
	"brew",
	"go",
	"python",
	"ruby",
	"cargo",
	"npm",
	"yarn",
	"pnpm",
	"claude",
	"Claude",
	"NewsToday",
	"newsd",
	"News",
	"CategoriesService",
	"assistantd",
	"Raycast",
	"WeatherWidget",
	"replicatord",
	"Rectangle",
	"zoom.us",
	"Discord",
	"Telegram",
	"Signal",
	"WhatsApp",
	"Microsoft",
	"Teams",
	"Outlook",
	"1Password",
	"Bitwarden",
	"Arc",
	"Brave",
	"Vivaldi",
	"Opera",
	"Edge",
	"cmux",
	"AMPDevicesAge",
	"AMPLibraryAge",
	"ControlCenter",
	"AirPlayXPCSer",
	"bluetoothd",
	"symptomsd",
	"CursorUIViewS",
	"Cursor",
}

// Suspicious ports
var suspiciousPorts = map[string]string{
	"4443":  "common C2 port",
	"8443":  "common C2 port",
	"1337":  "common backdoor port",
	"31337": "common backdoor port",
	"6667":  "IRC (sometimes C2)",
	"6697":  "IRC/TLS",
	"8000":  "common C2/staging port",
	"9001":  "Tor",
	"9050":  "Tor SOCKS",
}

var (
	dnsCache   = make(map[string]string)
	dnsCacheMu sync.Mutex
)

func resolveHost(ip string) string {
	dnsCacheMu.Lock()
	if cached, ok := dnsCache[ip]; ok {
		dnsCacheMu.Unlock()
		return cached
	}
	dnsCacheMu.Unlock()

	names, err := net.LookupAddr(ip)
	result := ""
	if err == nil && len(names) > 0 {
		result = strings.TrimSuffix(names[0], ".")
	}

	dnsCacheMu.Lock()
	dnsCache[ip] = result
	dnsCacheMu.Unlock()

	return result
}

func isKnownSafe(process string) bool {
	for _, prefix := range knownSafePrefixes {
		if strings.HasPrefix(process, prefix) {
			return true
		}
	}
	return false
}

// Temp directory prefixes where dropped payloads commonly execute from
var tempPrefixes = []string{
	"/tmp/",
	"/private/tmp/",
	"/private/var/",
	"/var/folders/",
}

// isTempPath checks if a process path looks like it's running from a temp directory
func isTempPath(process string) bool {
	lower := strings.ToLower(process)
	for _, prefix := range tempPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func classifyConnection(c *Connection) {
	// Check process name against known threat tools
	for name, reason := range suspiciousProcs() {
		if strings.Contains(c.Process, name) {
			c.Risk = RiskHigh
			c.Reason = reason
			return
		}
	}

	// Check remote host against known C2 domains
	host := c.RemoteHost
	if host == "" {
		host = c.RemoteAddr
	}
	for _, c2 := range knownC2() {
		if strings.Contains(host, c2) || strings.Contains(c.RemoteAddr, c2) {
			c.Risk = RiskHigh
			c.Reason = "known C2 domain: " + c2
			return
		}
	}

	// Binary running from temp directory with outbound connection = high risk
	if isTempPath(c.Process) && c.RemoteAddr != "" && c.RemoteAddr != "*:*" && c.State != "LISTEN" {
		c.Risk = RiskHigh
		c.Reason = "binary running from temp directory"
		return
	}

	// Check for suspicious ports
	if reason, ok := suspiciousPorts[c.RemotePort]; ok {
		c.Risk = RiskMedium
		c.Reason = reason
		return
	}

	// Check user trusted list
	trusted := LoadTrusted()
	if trusted.IsProcessTrusted(c.Process) {
		c.Risk = RiskLow
		c.Reason = "trusted by user"
		return
	}

	// Check if process is known safe
	if isKnownSafe(c.Process) {
		c.Risk = RiskLow
		c.Reason = "known process"
		return
	}

	// Unknown process with an outbound connection
	if c.RemoteAddr != "" && c.RemoteAddr != "*" {
		c.Risk = RiskMedium
		c.Reason = "unknown process"
	}
}

// parseLsofLine parses a single line of lsof -i output.
// lsof columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [STATE]
// We use +c 0 for full command names, but need to handle multi-word carefully.
func parseLsofLine(line string, header string) *Connection {
	// Use the header positions to parse fixed-width columns
	// Fallback: split by whitespace, COMMAND is first, PID is second
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return nil
	}

	// Find PID position - it's the first numeric field after the command
	// PID is always a pure integer, skip version-like strings (e.g. "2.1.87")
	pidIdx := -1
	for i := 1; i < len(fields); i++ {
		allDigit := true
		for _, ch := range fields[i] {
			if ch < '0' || ch > '9' {
				allDigit = false
				break
			}
		}
		if allDigit && len(fields[i]) > 0 {
			pidIdx = i
			break
		}
	}

	if pidIdx < 1 {
		return nil
	}

	// Everything before PID is the command name
	processName := strings.Join(fields[:pidIdx], " ")

	// If process name looks like a version string (e.g. "2.1.87"), it means
	// lsof split a multi-word command and we lost the real name. Skip these.
	if len(processName) > 0 && processName[0] >= '0' && processName[0] <= '9' {
		return nil
	}

	c := &Connection{
		Process: processName,
		PID:     fields[pidIdx],
		Count:   1,
	}

	// NODE field (TCP/UDP) - scan for it
	nodeIdx := -1
	for i := pidIdx + 1; i < len(fields); i++ {
		if fields[i] == "TCP" || fields[i] == "UDP" {
			nodeIdx = i
			c.Protocol = fields[i]
			break
		}
	}

	if nodeIdx < 0 || nodeIdx+1 >= len(fields) {
		return nil
	}

	// NAME is after NODE
	nameIdx := nodeIdx + 1
	nameField := fields[nameIdx]

	// Check for state in parentheses at end
	lastIdx := len(fields) - 1
	if strings.HasPrefix(fields[lastIdx], "(") {
		c.State = strings.Trim(fields[lastIdx], "()")
	}

	if strings.Contains(nameField, "->") {
		parts := strings.SplitN(nameField, "->", 2)
		c.LocalAddr = parts[0]
		c.RemoteAddr = parts[1]

		if lastColon := strings.LastIndex(c.LocalAddr, ":"); lastColon != -1 {
			c.LocalPort = c.LocalAddr[lastColon+1:]
		}

		if lastColon := strings.LastIndex(c.RemoteAddr, ":"); lastColon != -1 {
			c.RemotePort = c.RemoteAddr[lastColon+1:]
			remoteIP := c.RemoteAddr[:lastColon]
			c.RemoteHost = resolveHost(remoteIP)
		}
	} else {
		c.LocalAddr = nameField
		if lastColon := strings.LastIndex(c.LocalAddr, ":"); lastColon != -1 {
			c.LocalPort = c.LocalAddr[lastColon+1:]
		}
		c.State = "LISTEN"
	}

	return c
}

func ScanConnections() []Connection {
	out, err := exec.Command("lsof", "-i", "-n", "-P", "+c", "0").Output()
	if err != nil {
		return nil
	}

	now := time.Now()
	lines := strings.Split(string(out), "\n")

	// First line is the header
	header := ""
	if len(lines) > 0 {
		header = lines[0]
	}

	// Parse and deduplicate: group by process+remote
	type connKey struct {
		process    string
		remoteAddr string
		remotePort string
	}
	grouped := make(map[connKey]*Connection)
	var order []connKey

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		c := parseLsofLine(line, header)
		if c == nil {
			continue
		}
		c.FirstSeen = now

		key := connKey{c.Process, c.RemoteAddr, c.RemotePort}
		if existing, ok := grouped[key]; ok {
			existing.Count++
		} else {
			classifyConnection(c)
			grouped[key] = c
			order = append(order, key)
		}
	}

	conns := make([]Connection, 0, len(grouped))
	for _, key := range order {
		conns = append(conns, *grouped[key])
	}

	// Sort: high risk first, then medium, then by process name
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Risk != conns[j].Risk {
			return conns[i].Risk > conns[j].Risk
		}
		return conns[i].Process < conns[j].Process
	})

	return conns
}

// FormatCount returns a display string for grouped connections
func FormatCount(count int) string {
	if count <= 1 {
		return ""
	}
	return fmt.Sprintf(" ×%d", count)
}
