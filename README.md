# vigil

A live macOS security monitor TUI built in response to being targeted by [BlueNoroff (North Korean APT)](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/).

![Go](https://img.shields.io/badge/Go-1.22+-blue) ![macOS](https://img.shields.io/badge/macOS-only-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green)

## What it does

A terminal dashboard that monitors your Mac for signs of compromise:

- **Network Monitor** — Live auto-refreshing view of all outbound connections, risk-classified, with suspicious process and C2 domain detection
- **BlueNoroff IOC Scan** — Checks 30+ file paths and persistence locations from the [Kaspersky GhostCall/GhostHire report](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/)
- **LaunchAgent/Daemon Monitor** — Lists all persistence items, flags suspicious or third-party entries
- **Security Posture** — Firewall, SIP, FileVault, Gatekeeper, SSH status at a glance

## Install

```bash
# Clone and build
git clone https://github.com/smkly/vigil.git
cd vigil
go build -o vigil .
./vigil
```

For full network visibility, run with sudo:
```bash
sudo ./vigil
```

## Usage

| Key | Action |
|-----|--------|
| `←` `→` or `h` `l` | Switch tabs |
| `Tab` / `Shift+Tab` | Switch tabs |
| `j` `k` | Navigate / scroll |
| `t` | Trust selected process or launch item |
| `u` | Untrust selected item |
| `p` or `Space` | Pause/resume live refresh |
| `1` `2` `3` | Filter: all / outbound / suspicious |
| `r` | Refresh all scans |
| `q` | Quit |

Trusted items are saved to `~/.vigil/trusted.json` and persist across runs.

## Background

In early 2025, BlueNoroff (a North Korean state-sponsored threat actor) targeted developers and crypto professionals through fake job interviews and compromised meeting links. Their toolkit includes keyloggers, credential stealers, and backdoors that persist through LaunchAgents/Daemons.

This tool was built after a personal incident to help verify system integrity and share with others who may have been targeted.

### What BlueNoroff steals

Their `SilentSiphon` stealer suite targets:
- Crypto wallets (Exodus, MetaMask, Ledger, Coinbase, etc.)
- Cloud credentials (AWS, GCP, Azure)
- Dev tools (SSH keys, GitHub/GitLab tokens, npm/PyPI credentials)
- Browser data (Chrome, Brave, Arc, Edge)
- Password managers (1Password, Bitwarden, LastPass)
- Communication apps (Telegram, Slack)
- macOS Keychain

**If you were compromised, rotate ALL credentials immediately.**

## If you find IOCs

If `vigil` detects any indicators of compromise:

1. **Disconnect from the internet immediately**
2. **Do not try to "clean" the malware** — back up data and do a full OS reinstall
3. **Rotate all credentials** from a different, clean device
4. **Move crypto funds** to new wallets generated on the clean device
5. **Report the incident** to your organization's security team

## Recommended companion tools

- [LuLu](https://objective-see.org/products/lulu.html) — free, open-source outbound firewall (blocks connections in real-time)
- [BlockBlock](https://objective-see.org/products/blockblock.html) — alerts on new persistence mechanisms
- [OverSight](https://objective-see.org/products/oversight.html) — alerts on mic/camera access

vigil detects. LuLu prevents.

## License

MIT
