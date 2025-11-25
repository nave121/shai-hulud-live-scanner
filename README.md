# 🛡️ Shai-Hulud 2.0 Live Scanner

A simple incident response tool to scan your entire GitHub Organization for the malicious npm packages associated with the "Shai-Hulud" supply chain attack (Nov 2025).

## Why this tool?
The list of compromised packages is growing (currently 600+). Instead of manually checking static lists, this script:
1. **Fetches the latest IOCs** directly from the [Wiz Research Live List](https://github.com/wiz-sec-public/wiz-research-iocs).
2. **Scans all repositories** in your GitHub Organization using the `gh` CLI.
3. Checks `package.json` dependencies (dev & prod) against the infected versions.

## Prerequisites
* Python 3
* [GitHub CLI (`gh`)](https://cli.github.com/) installed and authenticated (`gh auth login`).

## Usage

```bash
python3 shai_hulud_scanner.py YOUR_ORG_NAME
```

## Disclaimer
This tool is provided "as is" to help the community. It scans for package names/versions in `package.json`. For a guaranteed clean bill of health, always verify against `package-lock.json` and use internal security tools.
