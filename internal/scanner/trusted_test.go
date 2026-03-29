package scanner

import "testing"

func TestIsProcessTrustedRequiresExactMatch(t *testing.T) {
	trusted := &TrustedList{Processes: []string{"Code"}}

	if !trusted.IsProcessTrusted("Code") {
		t.Fatal("expected exact process match to be trusted")
	}
	if trusted.IsProcessTrusted("Code Helper") {
		t.Fatal("did not expect prefix match to be trusted")
	}
}

func TestIsLaunchItemTrustedRequiresExactMatch(t *testing.T) {
	trusted := &TrustedList{LaunchItems: []string{"com.google.keystone.agent.plist"}}

	if !trusted.IsLaunchItemTrusted("com.google.keystone.agent.plist") {
		t.Fatal("expected exact launch item match to be trusted")
	}
	if trusted.IsLaunchItemTrusted("com.google.keystone.agent.extra.plist") {
		t.Fatal("did not expect substring match to be trusted")
	}
}
