package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/smkly/vigil/internal/scanner"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	tabStyle = lipgloss.NewStyle().
			Padding(0, 2)

	activeTabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Bold(true).
			Foreground(lipgloss.Color("#7D56F4")).
			Underline(true)

	okStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#04B575"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFAA00"))

	dangerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4444")).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA"))

	colHeaderStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#333333")).
			Padding(0, 1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	riskHighStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4444")).
			Bold(true)

	riskMedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFAA00"))

	riskLowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575"))
)

type tab int

const (
	tabNetwork tab = iota
	tabIOC
	tabLaunchd
	tabSecurity
)

var tabNames = []string{"Network", "IOC Scan", "LaunchAgents", "Security"}

const refreshInterval = 3 * time.Second

type model struct {
	activeTab   tab
	width       int
	height      int
	security    []scanner.SecurityCheck
	iocs        []scanner.IOCResult
	launchItems []scanner.LaunchItem
	connections []scanner.Connection
	scroll      int
	cursor      int // selected row
	lastRefresh time.Time
	paused      bool
	filter      string // "all", "outbound", "suspicious"
	trusted     *scanner.TrustedList
	statusMsg   string // temporary status message
	statusTime  time.Time
}

func (m *model) resetCursor() {
	m.cursor = 0
	m.scroll = 0
}

func (m model) clampedCursor(length int) int {
	if length <= 0 {
		return 0
	}
	if m.cursor < 0 {
		return 0
	}
	if m.cursor >= length {
		return length - 1
	}
	return m.cursor
}

func visibleRange(cursor, length, maxShow int) (int, int) {
	if length == 0 {
		return 0, 0
	}
	if maxShow < 1 {
		maxShow = 1
	}
	start := 0
	if cursor >= maxShow {
		start = cursor - maxShow + 1
	}
	end := start + maxShow
	if end > length {
		end = length
		start = end - maxShow
		if start < 0 {
			start = 0
		}
	}
	return start, end
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type scanDoneMsg struct {
	connections []scanner.Connection
}

func refreshNetwork() tea.Msg {
	return scanDoneMsg{connections: scanner.ScanConnections()}
}

type initialScanMsg struct {
	security    []scanner.SecurityCheck
	iocs        []scanner.IOCResult
	launchItems []scanner.LaunchItem
	connections []scanner.Connection
}

func initialScan() tea.Msg {
	return initialScanMsg{
		security:    scanner.ScanSecurity(),
		iocs:        scanner.ScanIOCs(),
		launchItems: scanner.ScanLaunchItems(),
		connections: scanner.ScanConnections(),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(initialScan, tickCmd())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab", "right", "l":
			m.activeTab = (m.activeTab + 1) % 4
			m.resetCursor()
		case "shift+tab", "left", "h":
			m.activeTab = (m.activeTab + 3) % 4
			m.resetCursor()
		case "r":
			return m, initialScan
		case "j", "down":
			m.cursor++
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "t":
			m.trustSelected()
		case "u":
			m.untrustSelected()
		case "p", " ":
			m.paused = !m.paused
		case "1":
			m.filter = "all"
			m.resetCursor()
		case "2":
			m.filter = "outbound"
			m.resetCursor()
		case "3":
			m.filter = "suspicious"
			m.resetCursor()
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case initialScanMsg:
		m.security = msg.security
		m.iocs = msg.iocs
		m.launchItems = msg.launchItems
		m.connections = msg.connections
		m.lastRefresh = time.Now()

	case tickMsg:
		if !m.paused && m.activeTab == tabNetwork {
			return m, tea.Batch(refreshNetwork, tickCmd())
		}
		return m, tickCmd()

	case scanDoneMsg:
		m.connections = msg.connections
		m.lastRefresh = time.Now()
	}

	return m, nil
}

func (m model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Title bar
	b.WriteString(titleStyle.Render(" vigil "))
	b.WriteString("  ")
	b.WriteString(subtitleStyle.Render("macOS Security Monitor"))

	// Status indicator
	if m.paused {
		b.WriteString("  ")
		b.WriteString(warnStyle.Render("[PAUSED]"))
	} else if m.activeTab == tabNetwork {
		b.WriteString("  ")
		b.WriteString(okStyle.Render("[LIVE]"))
	}
	b.WriteString("\n\n")

	// Tabs
	for i, name := range tabNames {
		if tab(i) == m.activeTab {
			b.WriteString(activeTabStyle.Render(name))
		} else {
			b.WriteString(tabStyle.Render(name))
		}
	}
	b.WriteString("\n\n")

	// Content
	contentWidth := m.width - 4
	if contentWidth < 60 {
		contentWidth = 60
	}

	switch m.activeTab {
	case tabNetwork:
		b.WriteString(m.renderNetwork(contentWidth))
	case tabIOC:
		b.WriteString(m.renderIOCs(contentWidth))
	case tabLaunchd:
		b.WriteString(m.renderLaunchd(contentWidth))
	case tabSecurity:
		b.WriteString(m.renderSecurity(contentWidth))
	}

	// Footer
	b.WriteString("\n")
	if m.activeTab == tabNetwork {
		b.WriteString(statusBarStyle.Render("  ←/→ tabs • p pause • t trust • u untrust • 1 all  2 outbound  3 suspicious • j/k scroll • r refresh • q quit"))
	} else if m.activeTab == tabLaunchd {
		b.WriteString(statusBarStyle.Render("  ←/→ tabs • t trust • u untrust • j/k scroll • r refresh • q quit"))
	} else {
		b.WriteString(statusBarStyle.Render("  ←/→ tabs • r refresh • j/k scroll • q quit"))
	}

	// Show temporary status message
	if m.statusMsg != "" && time.Since(m.statusTime) < 3*time.Second {
		b.WriteString("  ")
		b.WriteString(okStyle.Render(m.statusMsg))
	}

	if !m.lastRefresh.IsZero() {
		b.WriteString(statusBarStyle.Render(fmt.Sprintf("  • updated %s", m.lastRefresh.Format("15:04:05"))))
	}

	return b.String()
}

func (m model) filteredConnections() []scanner.Connection {
	filter := m.filter
	if filter == "" {
		filter = "outbound"
	}
	var filtered []scanner.Connection
	for _, c := range m.connections {
		switch filter {
		case "suspicious":
			if c.Risk >= scanner.RiskMedium {
				filtered = append(filtered, c)
			}
		case "outbound":
			if c.RemoteAddr != "" && c.RemoteAddr != "*:*" && c.State != "LISTEN" {
				filtered = append(filtered, c)
			}
		default:
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func (m *model) trustSelected() {
	switch m.activeTab {
	case tabNetwork:
		filtered := m.filteredConnections()
		cursor := m.clampedCursor(len(filtered))
		if len(filtered) > 0 {
			proc := filtered[cursor].Process
			m.trusted.TrustProcess(proc)
			m.trusted.Save()
			m.statusMsg = "Trusted: " + proc
			m.statusTime = time.Now()
			// Re-classify all connections
			m.connections = scanner.ScanConnections()
		}
	case tabLaunchd:
		cursor := m.clampedCursor(len(m.launchItems))
		if len(m.launchItems) > 0 {
			name := m.launchItems[cursor].Name
			m.trusted.TrustLaunchItem(name)
			m.trusted.Save()
			m.statusMsg = "Trusted: " + name
			m.statusTime = time.Now()
		}
	}
}

func (m *model) untrustSelected() {
	switch m.activeTab {
	case tabNetwork:
		filtered := m.filteredConnections()
		cursor := m.clampedCursor(len(filtered))
		if len(filtered) > 0 {
			proc := filtered[cursor].Process
			m.trusted.UntrustProcess(proc)
			m.trusted.Save()
			m.statusMsg = "Untrusted: " + proc
			m.statusTime = time.Now()
			m.connections = scanner.ScanConnections()
		}
	case tabLaunchd:
		cursor := m.clampedCursor(len(m.launchItems))
		if len(m.launchItems) > 0 {
			name := m.launchItems[cursor].Name
			m.trusted.UntrustLaunchItem(name)
			m.trusted.Save()
			m.statusMsg = "Untrusted: " + name
			m.statusTime = time.Now()
		}
	}
}

func (m model) renderNetwork(width int) string {
	var b strings.Builder

	// Summary bar
	total := len(m.connections)
	outbound := 0
	suspicious := 0
	high := 0
	medium := 0

	for _, c := range m.connections {
		if c.RemoteAddr != "" && c.RemoteAddr != "*:*" && c.State != "LISTEN" {
			outbound++
		}
		if c.Risk >= scanner.RiskMedium {
			suspicious++
		}
		if c.Risk == scanner.RiskHigh {
			high++
		}
		if c.Risk == scanner.RiskMedium {
			medium++
		}
	}

	// Stats line
	stats := fmt.Sprintf("  %s %d    %s %d    ",
		dimStyle.Render("Total:"), total,
		dimStyle.Render("Outbound:"), outbound)

	if high > 0 {
		stats += dangerStyle.Render(fmt.Sprintf("HIGH RISK: %d", high)) + "    "
	}
	if medium > 0 {
		stats += warnStyle.Render(fmt.Sprintf("Medium: %d", medium)) + "    "
	}
	if high == 0 && medium == 0 {
		stats += okStyle.Render("No suspicious connections")
	}
	b.WriteString(stats)
	b.WriteString("\n\n")

	// Filter connections
	filter := m.filter
	if filter == "" {
		filter = "outbound"
	}

	filtered := m.filteredConnections()

	// Filter indicator
	filterLabels := map[string]string{
		"all":        "[1] ALL",
		"outbound":   "[2] OUTBOUND",
		"suspicious": "[3] SUSPICIOUS",
	}
	for _, f := range []string{"all", "outbound", "suspicious"} {
		if f == filter {
			b.WriteString("  " + activeTabStyle.Render(filterLabels[f]))
		} else {
			b.WriteString("  " + dimStyle.Render(filterLabels[f]))
		}
	}
	b.WriteString("\n\n")

	if len(filtered) == 0 {
		if filter == "suspicious" {
			b.WriteString(okStyle.Render("  No suspicious connections detected"))
		} else {
			b.WriteString(dimStyle.Render("  No connections to show"))
		}
		return b.String()
	}

	// Column header
	b.WriteString(fmt.Sprintf("  %-5s %-20s %-7s %-30s %-6s %s\n",
		colHeaderStyle.Render("RISK"),
		colHeaderStyle.Render("PROCESS"),
		colHeaderStyle.Render("PID"),
		colHeaderStyle.Render("REMOTE"),
		colHeaderStyle.Render("PORT"),
		colHeaderStyle.Render("DETAIL")))

	sep := dimStyle.Render("  " + strings.Repeat("─", width-4))
	b.WriteString(sep)
	b.WriteString("\n")

	// Clamp cursor
	cursor := m.clampedCursor(len(filtered))

	// Scrollable window around cursor
	maxShow := m.height - 16
	if maxShow < 5 {
		maxShow = 5
	}
	start, end := visibleRange(cursor, len(filtered), maxShow)

	for idx := start; idx < end; idx++ {
		c := filtered[idx]
		isSelected := idx == cursor

		process := truncate(c.Process, 20)
		remote := c.RemoteHost
		if remote == "" {
			remote = c.RemoteAddr
		}
		if strings.Contains(remote, ":") {
			if i := strings.LastIndex(remote, ":"); i != -1 {
				remote = remote[:i]
			}
		}
		remote = truncate(remote, 30)

		var riskLabel string
		var lineStyle lipgloss.Style
		switch c.Risk {
		case scanner.RiskHigh:
			riskLabel = riskHighStyle.Render("▲ HIGH")
			lineStyle = riskHighStyle
		case scanner.RiskMedium:
			riskLabel = riskMedStyle.Render("● MED ")
			lineStyle = riskMedStyle
		case scanner.RiskLow:
			riskLabel = okStyle.Render("  OK  ")
			lineStyle = dimStyle
		default:
			riskLabel = dimStyle.Render("  ·   ")
			lineStyle = dimStyle
		}

		detail := c.Reason
		countStr := scanner.FormatCount(c.Count)
		if countStr != "" {
			detail += dimStyle.Render(countStr)
		}
		if c.State != "" && c.State != "ESTABLISHED" {
			if detail != "" {
				detail += " "
			}
			detail += dimStyle.Render("(" + c.State + ")")
		}

		// Cursor indicator
		prefix := "  "
		if isSelected {
			prefix = "▸ "
		}

		if c.Risk >= scanner.RiskMedium {
			b.WriteString(fmt.Sprintf("%s%s %-20s %-7s %-30s %-6s %s\n",
				prefix,
				riskLabel,
				lineStyle.Render(process),
				lineStyle.Render(c.PID),
				lineStyle.Render(remote),
				lineStyle.Render(c.RemotePort),
				lineStyle.Render(detail)))
		} else {
			b.WriteString(fmt.Sprintf("%s%s %-20s %-7s %-30s %-6s %s\n",
				prefix,
				riskLabel,
				process,
				dimStyle.Render(c.PID),
				dimStyle.Render(remote),
				dimStyle.Render(c.RemotePort),
				dimStyle.Render(detail)))
		}
	}

	if end < len(filtered) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("\n  ↓ %d more", len(filtered)-end)))
	}
	if start > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↑ %d above", start)))
	}

	return b.String()
}

func (m model) renderIOCs(width int) string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("  Checking known malware paths"))
	b.WriteString("\n\n")

	found := 0
	for _, ioc := range m.iocs {
		if ioc.Found {
			found++
		}
	}

	if found == 0 {
		b.WriteString(okStyle.Render(fmt.Sprintf("  ✓ All clear — %d paths checked, no IOCs found", len(m.iocs))))
	} else {
		b.WriteString(dangerStyle.Render(fmt.Sprintf("  ✗ WARNING: %d IOC(s) detected!", found)))
	}
	b.WriteString("\n\n")

	maxShow := m.height - 14
	if maxShow < 5 {
		maxShow = 5
	}
	cursor := m.clampedCursor(len(m.iocs))
	start, end := visibleRange(cursor, len(m.iocs), maxShow)

	for idx := start; idx < end; idx++ {
		ioc := m.iocs[idx]
		prefix := "  "
		if idx == cursor {
			prefix = "▸ "
		}
		if ioc.Found {
			b.WriteString(dangerStyle.Render(fmt.Sprintf("%s✗ FOUND  %s\n", prefix, ioc.Path)))
			b.WriteString(dangerStyle.Render(fmt.Sprintf("           %s\n", ioc.Detail)))
		} else {
			b.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, okStyle.Render("✓"), dimStyle.Render(ioc.Path)))
		}
	}

	if end < len(m.iocs) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("\n  ... %d more (j/k to scroll)", len(m.iocs)-end)))
	}
	if start > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↑ %d above", start)))
	}

	return b.String()
}

func (m model) renderLaunchd(width int) string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("  LaunchAgents & LaunchDaemons"))
	b.WriteString("\n\n")

	if len(m.launchItems) == 0 {
		b.WriteString(okStyle.Render("  ✓ No LaunchAgents or LaunchDaemons found (clean system)"))
		return b.String()
	}

	suspicious := 0
	thirdParty := 0
	for _, item := range m.launchItems {
		if item.Suspicious {
			suspicious++
		} else if item.Reason == "third-party" {
			thirdParty++
		}
	}

	if suspicious > 0 {
		b.WriteString(dangerStyle.Render(fmt.Sprintf("  ✗ %d suspicious item(s) detected!\n\n", suspicious)))
	} else {
		b.WriteString(okStyle.Render(fmt.Sprintf("  ✓ %d items found, none suspicious", len(m.launchItems))))
		if thirdParty > 0 {
			b.WriteString(warnStyle.Render(fmt.Sprintf(" (%d third-party)", thirdParty)))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	maxShow := m.height - 14
	if maxShow < 3 {
		maxShow = 3
	}
	cursor := m.clampedCursor(len(m.launchItems))
	start, end := visibleRange(cursor, len(m.launchItems), maxShow)

	for idx := start; idx < end; idx++ {
		item := m.launchItems[idx]
		isSelected := idx == m.cursor
		prefix := "  "
		if isSelected {
			prefix = "▸ "
		}

		isTrusted := m.trusted.IsLaunchItemTrusted(item.Name)

		if item.Suspicious {
			b.WriteString(dangerStyle.Render(fmt.Sprintf("%s✗ %s\n", prefix, item.Name)))
			b.WriteString(dangerStyle.Render(fmt.Sprintf("    %s — %s\n", item.Location, item.Reason)))
			b.WriteString(dangerStyle.Render(fmt.Sprintf("    %s\n", item.Path)))
		} else if isTrusted {
			b.WriteString(fmt.Sprintf("%s%s  %s %s\n", prefix, okStyle.Render("✓"), item.Name, okStyle.Render("(trusted)")))
			b.WriteString(fmt.Sprintf("     %s\n", dimStyle.Render(item.Location)))
		} else if item.Reason == "third-party" {
			b.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, warnStyle.Render("?"), item.Name))
			b.WriteString(fmt.Sprintf("     %s\n", dimStyle.Render(item.Location+" — third-party (press t to trust)")))
		} else {
			b.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, okStyle.Render("✓"), dimStyle.Render(item.Name)))
		}
	}

	if end < len(m.launchItems) {
		b.WriteString(dimStyle.Render(fmt.Sprintf("\n  ... %d more (j/k to scroll)", len(m.launchItems)-end)))
	}
	if start > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↑ %d above", start)))
	}

	return b.String()
}

func (m model) renderSecurity(width int) string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("  System Security Posture"))
	b.WriteString("\n\n")

	for _, check := range m.security {
		var icon, status string
		if check.OK {
			icon = okStyle.Render("✓")
			status = okStyle.Render(check.Status)
		} else {
			icon = dangerStyle.Render("✗")
			status = dangerStyle.Render(check.Status)
		}
		b.WriteString(fmt.Sprintf("  %s  %-32s %s\n", icon, check.Name, status))
	}

	ok := 0
	for _, c := range m.security {
		if c.OK {
			ok++
		}
	}
	b.WriteString("\n")
	total := len(m.security)
	if ok == total {
		b.WriteString(okStyle.Render(fmt.Sprintf("  All %d checks passed", total)))
	} else {
		b.WriteString(dangerStyle.Render(fmt.Sprintf("  %d/%d checks passed", ok, total)))
	}

	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func runBaseline() {
	fmt.Println(titleStyle.Render(" vigil ") + "  " + subtitleStyle.Render("First-run setup"))
	fmt.Println()
	fmt.Println("  Scanning current processes and launch items to establish a baseline...")
	fmt.Println()

	procs := scanner.BaselineProcesses()
	launchItems := scanner.BaselineLaunchItems()

	fmt.Println(headerStyle.Render("  Network processes found:"))
	for _, p := range procs {
		fmt.Println("    " + okStyle.Render("✓") + "  " + p)
	}
	fmt.Println()

	if len(launchItems) > 0 {
		fmt.Println(headerStyle.Render("  Launch items found:"))
		for _, l := range launchItems {
			fmt.Println("    " + okStyle.Render("✓") + "  " + l)
		}
		fmt.Println()
	}

	fmt.Printf("  Trust all %d processes and %d launch items? [Y/n] ", len(procs), len(launchItems))

	var answer string
	fmt.Scanln(&answer)

	if answer == "" || answer == "y" || answer == "Y" || answer == "yes" {
		trusted := scanner.LoadTrusted()
		trusted.TrustBaseline(procs, launchItems)
		trusted.Save()
		fmt.Println()
		fmt.Println(okStyle.Render("  ✓ Baseline saved to ~/.vigil/trusted.json"))
		fmt.Println(dimStyle.Render("  New processes will show as warnings going forward."))
	} else {
		fmt.Println()
		fmt.Println(dimStyle.Render("  Skipped. You can trust items individually with 't' in the dashboard."))
	}
	fmt.Println()
}

func main() {
	// First-run baseline
	if scanner.IsFirstRun() {
		runBaseline()
	}

	m := model{
		activeTab: tabNetwork,
		filter:    "outbound",
		trusted:   scanner.LoadTrusted(),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
