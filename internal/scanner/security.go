package scanner

import (
	"fmt"
	"os/exec"
	"strings"
)

type SecurityCheck struct {
	Name   string
	Status string
	OK     bool
	Detail string
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

	s, err := commandOutput("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err != nil {
		checks = append(checks, unknownCheck("Firewall", err))
	} else {
		enabled := strings.Contains(s, "enabled")
		checks = append(checks, SecurityCheck{
			Name:   "Firewall",
			Status: boolStatus(enabled),
			OK:     enabled,
			Detail: s,
		})
	}

	s, err = commandOutput("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode")
	if err != nil {
		checks = append(checks, unknownCheck("Stealth Mode", err))
	} else {
		stealth := strings.Contains(s, " on")
		checks = append(checks, SecurityCheck{
			Name:   "Stealth Mode",
			Status: boolStatus(stealth),
			OK:     stealth,
			Detail: s,
		})
	}

	return checks
}

func checkSIP() SecurityCheck {
	s, err := commandOutput("csrutil", "status")
	if err != nil {
		return unknownCheck("System Integrity Protection", err)
	}
	enabled := strings.Contains(s, "enabled")
	return SecurityCheck{
		Name:   "System Integrity Protection",
		Status: boolStatus(enabled),
		OK:     enabled,
		Detail: s,
	}
}

func checkFileVault() SecurityCheck {
	s, err := commandOutput("fdesetup", "status")
	if err != nil {
		return unknownCheck("FileVault", err)
	}
	on := strings.Contains(s, "On")
	return SecurityCheck{
		Name:   "FileVault",
		Status: boolStatus(on),
		OK:     on,
		Detail: s,
	}
}

func checkGatekeeper() SecurityCheck {
	s, err := commandOutput("spctl", "--status")
	if err != nil {
		return unknownCheck("Gatekeeper", err)
	}
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
	out, err := exec.Command("launchctl", "print", "system/com.apple.sshd").CombinedOutput()
	s := strings.TrimSpace(string(out))
	disabled := strings.Contains(s, "Could not find service")
	if err != nil && !disabled {
		return unknownCheck("Remote Login (SSH)", fmt.Errorf("%v: %s", err, s))
	}
	return SecurityCheck{
		Name:   "Remote Login (SSH)",
		Status: ternary(disabled, "Off", "On"),
		OK:     disabled, // SSH off is safer
		Detail: ternary(disabled, "SSH server is not running", "SSH server is active — disable if not needed"),
	}
}

func commandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if s == "" {
			return "", err
		}
		return s, fmt.Errorf("%v: %s", err, s)
	}
	return s, nil
}

func unknownCheck(name string, err error) SecurityCheck {
	return SecurityCheck{
		Name:   name,
		Status: "Unknown",
		OK:     false,
		Detail: err.Error(),
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
