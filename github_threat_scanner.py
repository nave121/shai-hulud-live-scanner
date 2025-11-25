#!/usr/bin/env python3
"""
General GitHub Organization Threat Scanner
------------------------------------------
A specialized security tool to detect supply chain compromises, 
malicious persistence mechanisms, and compromised runners across 
an entire GitHub Organization.

Usage:
    python github_threat_scanner.py --org Navina-ai
    python github_threat_scanner.py --org Navina-ai --limit 50 --verbose

Dependencies:
    - GitHub CLI ('gh') must be installed and authenticated.
    - Python 3.8+
"""

import argparse
import csv
import io
import json
import subprocess
import sys
import urllib.request
from datetime import datetime
from pathlib import PurePosixPath
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Any

# --- 1. CENTRALIZED THREAT CONFIGURATION ---
# Edit this section to add new threats without changing code logic.
THREAT_CONFIG = {
    "malicious_filenames": {
        "setup_bun.js", "bun_environment.js", 
        "cloud.json", "contents.json", 
        "environment.json", "truffleSecrets.json",
        "memdump.py" # Example from other campaigns
    },
    "suspicious_workflow_patterns": [
        {"pattern": "runs-on: self-hosted", "risk": "High", "desc": "Self-hosted runner usage (potential persistence target)"},
        {"pattern": "discussion:", "risk": "Critical", "desc": "Workflow triggered by 'discussion' (Backdoor Indicator)"},
        {"pattern": "tojson(secrets)", "risk": "Critical", "desc": "Secrets serialization (Exfiltration Indicator)"},
        {"pattern": "curl ", "risk": "Low", "desc": "Network call in workflow (Requires manual review)"}
    ],
    "suspicious_runner_names": ["HULUD", "SHA1", "TEST", "DEBUG"],
    "campaign_markers": ["shai-hulud", "sha1hulud"],
    "ignored_directories": {"node_modules", ".git", "dist", "build", "vendor"},
    "intel_feed_url": "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
}

@dataclass
class Finding:
    repo: str
    risk_level: str  # Critical, High, Medium, Low
    category: str    # Dependency, Workflow, Infrastructure, Artifact
    location: str
    details: str

    def to_dict(self):
        return asdict(self)

# --- 2. UTILITY FUNCTIONS ---

def log(msg: str, type: str = "INFO", verbose: bool = False):
    if type == "DEBUG" and not verbose:
        return
    icons = {"INFO": "ℹ️", "WARN": "⚠️", "CRIT": "🚨", "GOOD": "✅", "DEBUG": "🐛"}
    print(f"{icons.get(type, '')}  [{type}] {msg}")

def run_gh_cmd(args: List[str]) -> Optional[str]:
    """Executes a GitHub CLI command and returns stdout."""
    try:
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            return None
        return result.stdout
    except FileNotFoundError:
        log("GitHub CLI ('gh') not found. Please install it.", "CRIT")
        sys.exit(1)

def fetch_intel_feed(url: str) -> Dict[str, Set[str]]:
    """Fetches dynamic list of malicious packages from an external source."""
    log(f"Fetching latest threat intel from {url}...", "INFO")
    try:
        with urllib.request.urlopen(url) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        
        db = {}
        reader = csv.DictReader(io.StringIO(content))
        count = 0
        for row in reader:
            # Normalize column names for generality
            pkg = row.get("Package Name") or row.get("Package")
            ver = row.get("Version")
            if pkg:
                if pkg not in db: db[pkg] = set()
                if ver:
                    clean_vers = ver.replace("=", " ").replace("||", " ").replace(",", " ").split()
                    db[pkg].update(clean_vers)
                count += 1
        log(f"Loaded {len(db)} malicious package signatures.", "GOOD")
        return db
    except Exception as e:
        log(f"Failed to fetch intel feed: {e}", "WARN")
        return {}

# --- 3. SCANNING MODULES ---

def scan_runners(org: str) -> List[Finding]:
    """Audits Organization-level Self-Hosted Runners."""
    log(f"Auditing runners for organization: {org}", "INFO")
    data = run_gh_cmd(["gh", "api", f"orgs/{org}/actions/runners", "--paginate"])
    findings = []
    
    if data:
        try:
            runners = json.loads(data).get("runners", [])
            for r in runners:
                name = r.get("name", "")
                status = r.get("status", "unknown")
                # Check for suspicious names
                if any(s in name.upper() for s in THREAT_CONFIG["suspicious_runner_names"]):
                    findings.append(Finding(
                        repo="<ORG_INFRASTRUCTURE>",
                        risk_level="Critical",
                        category="Infrastructure",
                        location=f"Runner ID: {r.get('id')}",
                        details=f"Suspicious Runner Name: '{name}' (Status: {status})"
                    ))
        except json.JSONDecodeError:
            log("Failed to parse runner API response.", "WARN")
    return findings

def scan_repo_contents(org: str, repo_name: str, branch: str, malware_db: Dict[str, Set[str]]) -> List[Finding]:
    """Deep scans a single repository using the Tree API."""
    findings = []
    
    # Fetch Git Tree (Recursive)
    tree_data = run_gh_cmd(["gh", "api", f"repos/{org}/{repo_name}/git/trees/{branch}?recursive=1"])
    if not tree_data:
        return []

    try:
        tree = json.loads(tree_data)
        if tree.get("truncated"):
            log(f"Tree truncated for {repo_name} - scan may be partial.", "WARN")
        
        paths = [item["path"] for item in tree.get("tree", []) if item["type"] == "blob"]
    except json.JSONDecodeError:
        return []

    # Iterate files
    for path in paths:
        # Skip ignored dirs
        if any(ignored in path for ignored in THREAT_CONFIG["ignored_directories"]):
            continue
            
        filename = PurePosixPath(path).name
        lower_path = path.lower()

        # [A] Artifact Check
        if filename in THREAT_CONFIG["malicious_filenames"]:
            findings.append(Finding(
                repo=repo_name, risk_level="High", category="Artifact",
                location=path, details=f"Known malware artifact found: {filename}"
            ))

        # [B] Workflow Analysis
        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            content = run_gh_cmd(["gh", "api", f"repos/{org}/{repo_name}/contents/{path}", "-H", "Accept: application/vnd.github.raw"])
            if content:
                lower_content = content.lower()
                for pattern in THREAT_CONFIG["suspicious_workflow_patterns"]:
                    if pattern["pattern"] in lower_content:
                        # Refine: Only flag if specifically relevant
                        findings.append(Finding(
                            repo=repo_name, risk_level=pattern["risk"], category="Workflow",
                            location=path, details=pattern["desc"]
                        ))
                
                # General Hygiene: Check for Unpinned Actions (e.g., uses: actions/checkout@v2)
                if "@v" in lower_content and "sha" not in lower_content:
                     findings.append(Finding(
                        repo=repo_name, risk_level="Low", category="Hygiene",
                        location=path, details="GitHub Action not pinned to SHA (Supply Chain Risk)"
                    ))

        # [C] Package.json Analysis (Deps & Scripts)
        if filename == "package.json":
            content = run_gh_cmd(["gh", "api", f"repos/{org}/{repo_name}/contents/{path}", "-H", "Accept: application/vnd.github.raw"])
            if content:
                try:
                    pkg_json = json.loads(content)
                    
                    # Check Deps
                    all_deps = {**pkg_json.get("dependencies", {}), **pkg_json.get("devDependencies", {})}
                    for pkg, ver in all_deps.items():
                        if pkg in malware_db:
                            findings.append(Finding(
                                repo=repo_name, risk_level="High", category="Dependency",
                                location=path, details=f"Malicious Package: {pkg} ({ver})"
                            ))
                    
                    # Check Scripts
                    for script, cmd in pkg_json.get("scripts", {}).items():
                        if any(bad in cmd for bad in THREAT_CONFIG["malicious_filenames"]):
                            findings.append(Finding(
                                repo=repo_name, risk_level="Critical", category="Malware Script",
                                location=f"{path} -> scripts['{script}']", details=f"Script executes malware artifact: {cmd}"
                            ))
                except json.JSONDecodeError:
                    pass

        # [D] Lockfile Analysis (Transitive)
        if filename in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
            content = run_gh_cmd(["gh", "api", f"repos/{org}/{repo_name}/contents/{path}", "-H", "Accept: application/vnd.github.raw"])
            if content:
                for mal_pkg in malware_db:
                    # Simple string search is fastest for massive lockfiles
                    if f'"{mal_pkg}"' in content or f'{mal_pkg}@' in content:
                        findings.append(Finding(
                            repo=repo_name, risk_level="Medium", category="Transitive Dependency",
                            location=path, details=f"Reference to malicious package '{mal_pkg}' found in lockfile"
                        ))

    return findings

# --- 4. MAIN CONTROLLER ---

def main():
    parser = argparse.ArgumentParser(description="General GitHub Organization Threat Scanner")
    parser.add_argument("--org", required=True, help="GitHub Organization name")
    parser.add_argument("--limit", type=int, default=1000, help="Max repos to scan")
    parser.add_argument("--repo", help="Scan a single specific repo only")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logs")
    parser.add_argument("--output", default=f"scan_report_{int(datetime.now().timestamp())}.json", help="Output JSON file")
    
    args = parser.parse_args()
    
    print(f"""
    🛡️  GITHUB THREAT SCANNER (GENERALIZED)
    ========================================
    Target Org:  {args.org}
    Scan Limit:  {args.limit}
    Output File: {args.output}
    ----------------------------------------
    """)

    # 1. Setup
    malware_db = fetch_intel_feed(THREAT_CONFIG["intel_feed_url"])
    all_findings = []

    # 2. Infra Scan
    runner_issues = scan_runners(args.org)
    all_findings.extend(runner_issues)

    # 3. Repo Fetch
    if args.repo:
        repos = [{"name": args.repo, "defaultBranchRef": {"name": "main"}}] # Simplified for single mode
    else:
        log("Fetching repository list...", "INFO")
        repos_raw = run_gh_cmd(["gh", "repo", "list", args.org, "--limit", str(args.limit), "--no-archived", "--json", "name,defaultBranchRef,description"])
        repos = json.loads(repos_raw) if repos_raw else []

    log(f"Starting scan on {len(repos)} repositories...", "INFO")

    # 4. Repo Scan Loop
    for i, repo in enumerate(repos):
        name = repo['name']
        branch = repo.get('defaultBranchRef', {}).get('name', 'main')
        
        # Progress Bar
        print(f"    Scanning [{i+1}/{len(repos)}]: {name:<40}", end='\r')
        
        # Meta Check
        desc = (repo.get('description') or "").lower()
        if any(m in desc for m in THREAT_CONFIG["campaign_markers"]):
            all_findings.append(Finding(name, "High", "Defacement", "Description", "Repo description contains threat actor marker"))

        # Deep Scan
        findings = scan_repo_contents(args.org, name, branch, malware_db)
        all_findings.extend(findings)

    print("\n" + "-"*50)

    # 5. Reporting
    criticals = [f for f in all_findings if f.risk_level in ["Critical", "High"]]
    
    if all_findings:
        log(f"Scan Complete. Found {len(all_findings)} issues ({len(criticals)} Critical/High).", "WARN")
        
        # Save JSON
        with open(args.output, "w") as f:
            json.dump([f.to_dict() for f in all_findings], f, indent=2)
        log(f"Full report saved to: {args.output}", "GOOD")
        
        # Print Summary to Console
        if criticals:
            print("\n🚨 CRITICAL FINDINGS SUMMARY:")
            for f in criticals:
                print(f"  • [{f.repo}] {f.category}: {f.details}")
    else:
        log("Scan Complete. No threats detected.", "GOOD")

if __name__ == "__main__":
    main()
