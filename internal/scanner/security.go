package scanner

import (
	"os/exec"
	"strings"
)

type SecurityCheck struct {
	Name    string
	Status  string
	OK      bool
	Detail  string
}

func ScanSecurity() []SecurityCheck {
	var checks []SecurityCheck

	// Firewall
	checks = append(checks, checkFirewall()...)

	// SIP
	checks = append(checks, checkSIP())

	// FileVault
	checks = append(checks, checkFileVault())

	// Gatekeeper
	checks = append(checks, checkGatekeeper())

	// Remote Login (SSH)
	checks = append(checks, checkRemoteLogin())

	return checks
}

func checkFirewall() []SecurityCheck {
	var checks []SecurityCheck

	out, _ := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output()
	s := strings.TrimSpace(string(out))
	enabled := strings.Contains(s, "enabled")
	checks = append(checks, SecurityCheck{
		Name:   "Firewall",
		Status: boolStatus(enabled),
		OK:     enabled,
		Detail: s,
	})

	out, _ = exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode").Output()
	s = strings.TrimSpace(string(out))
	stealth := strings.Contains(s, " on")
	checks = append(checks, SecurityCheck{
		Name:   "Stealth Mode",
		Status: boolStatus(stealth),
		OK:     stealth,
		Detail: s,
	})

	return checks
}

func checkSIP() SecurityCheck {
	out, _ := exec.Command("csrutil", "status").Output()
	s := strings.TrimSpace(string(out))
	enabled := strings.Contains(s, "enabled")
	return SecurityCheck{
		Name:   "System Integrity Protection",
		Status: boolStatus(enabled),
		OK:     enabled,
		Detail: s,
	}
}

func checkFileVault() SecurityCheck {
	out, _ := exec.Command("fdesetup", "status").Output()
	s := strings.TrimSpace(string(out))
	on := strings.Contains(s, "On")
	return SecurityCheck{
		Name:   "FileVault",
		Status: boolStatus(on),
		OK:     on,
		Detail: s,
	}
}

func checkGatekeeper() SecurityCheck {
	out, _ := exec.Command("spctl", "--status").Output()
	s := strings.TrimSpace(string(out))
	enabled := strings.Contains(s, "enabled")
	return SecurityCheck{
		Name:   "Gatekeeper",
		Status: boolStatus(enabled),
		OK:     enabled,
		Detail: s,
	}
}

func checkRemoteLogin() SecurityCheck {
	// Check if sshd is loaded
	out, _ := exec.Command("launchctl", "print", "system/com.apple.sshd").CombinedOutput()
	s := strings.TrimSpace(string(out))
	disabled := strings.Contains(s, "Could not find service")
	return SecurityCheck{
		Name:   "Remote Login (SSH)",
		Status: ternary(disabled, "Off", "On"),
		OK:     disabled, // SSH off is safer
		Detail: ternary(disabled, "SSH server is not running", "SSH server is active — disable if not needed"),
	}
}

func boolStatus(ok bool) string {
	if ok {
		return "Enabled"
	}
	return "Disabled"
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
