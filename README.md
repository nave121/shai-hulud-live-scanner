# 🛡️ GitHub Organization Threat Scanner

A specialized security tool designed to detect supply chain compromises, malicious persistence mechanisms, and compromised infrastructure across an entire GitHub Organization. 

> **Note:** Originally developed to detect the [Shai-Hulud 2.0 / Sha1-Hulud](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack) supply chain attack (Nov 2025), this tool has been generalized to hunt for broad classes of CI/CD compromise.

## 🚀 Capabilities

Unlike standard dependency scanners, this tool focuses on **Attack Persistence** and **Infrastructure Compromise**:

1.  **Infrastructure Audit**: Detects rogue **Self-Hosted Runners** registered by attackers (e.g., runners named `SHA1HULUD` or `DEBUG`).
2.  **Workflow Analysis**: Scans `.github/workflows` for:
    * **Backdoors**: Triggers based on `discussion_created` (allows external command execution).
    * **Exfiltration**: Workflows exporting `toJSON(secrets)`.
    * **Hygiene**: Unpinned GitHub Actions (e.g., `uses: actions/checkout@v2` instead of SHA pinning).
3.  **Deep Artifact Scanning**: Uses the GitHub Recursive Tree API to hunt for malware debris buried deep in repositories (e.g., `setup_bun.js`, `cloud.json`).
4.  **Live Intel**: Automatically fetches the latest malicious package list from **Wiz Research** (no manual updates needed).
5.  **Transitive Dependency Checks**: Scans `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` for hidden malicious sub-dependencies.

## 🛠️ Prerequisites

1.  **Python 3.8+**
2.  **GitHub CLI (`gh`)**: Must be installed and authenticated.
    ```bash
    # MacOS (Homebrew)
    brew install gh

    # Windows (Winget)
    winget install GitHub.cli

    # Login (Required)
    gh auth login
    ```

## 📦 Usage

### 1. General Organization Scan
Scans all repositories in the organization (default limit: 1000).
```bash
python github_threat_scanner.py --org Your-Org-Name
```

## 2. Specific Repository (Fast Check)
Target a single repository for a deep dive.
```bash
python github_threat_scanner.py --org Your-Org-Name --repo critical-service-api
```

## 3. Debug Mode
Show verbose logging for API calls and file processing.
```bash
python github_threat_scanner.py --org Your-Org-Name --verbose
```

## 📊 Reports
The tool outputs a detailed JSON report (e.g., scan_report_1732456789.json) and prints a summary to the console.
Critical Findings to Watch:

- `[Infrastructure] Suspicious Runner Name`: P0 Incident. An attacker has likely registered a runner to execute code in your environment.
- `[Workflow] Backdoor Indicator`: P0 Incident. A workflow exists that allows arbitrary code execution from external triggers.
- `[Artifact] Known malware artifact`: P1 Incident. Malware files (like setup_bun.js) were found in your file tree.

⚙️ Configuration
You can customize the detection logic by editing the THREAT_CONFIG dictionary at the top of the script:
```python
THREAT_CONFIG = {
    "malicious_filenames": {"setup_bun.js", "bun_environment.js", ...},
    "suspicious_runner_names": ["HULUD", "SHA1", ...],
    ...
}
```

## ⚠️ Disclaimer
This tool scans GitHub state via the API. It does not scan local developer machines. "Clean" results here mean your remote repositories and GitHub infrastructure appear clean. Developers should still rotate credentials if a breach is suspected.
