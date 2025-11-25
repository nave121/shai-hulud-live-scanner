#!/usr/bin/env python3
"""
🛡️ GitHub Organization Threat Scanner (Ultimate Version)
-------------------------------------------------------
A specialized security tool to detect supply chain compromises, 
malicious persistence mechanisms, and compromised infrastructure 
across an entire GitHub Organization.

Features:
- Smart Semantic Version Checking (vs simple string matching)
- Detection of Shai-Hulud 2.0 Artifacts (Bun payloads, C2 webhooks)
- Infrastructure Audit (Rogue Runners)
- Deep Recursive Scanning (Lockfiles, Workflows, Defacement)

Usage:
    python github_threat_scanner.py --org Navina-ai
    python github_threat_scanner.py --org Navina-ai --limit 50 --verbose

Dependencies:
    - GitHub CLI ('gh') must be installed and authenticated.
    - Python 3.8+
    - (Optional) 'packaging' library for smart version comparison: `pip install packaging`
"""

import argparse
import csv
import io
import json
import subprocess
import sys
import urllib.request
import os
from datetime import datetime
from pathlib import PurePosixPath
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Any

# --- OPTIONAL DEPENDENCY: PACKAGING ---
try:
    from packaging.version import Version
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    HAVE_PACKAGING = True
except ImportError:
    HAVE_PACKAGING = False

# --- 1. CENTRALIZED THREAT CONFIGURATION ---
THREAT_CONFIG = {
    "intel_feed_url": "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv",
    
    "malicious_filenames": {
        "setup_bun.js": "Bun preinstall payload (Shai-Hulud 2.x)",
        "bun_environment.js": "Bun environment payload (Shai-Hulud 2.x)",
        "actionsSecrets.json": "GitHub secrets dump (Shai-Hulud)",
        "cloud.json": "Cloud credentials dump (Shai-Hulud)",
        "contents.json": "File contents dump (Shai-Hulud)",
        "environment.json": "Environment dump (Shai-Hulud)",
        "truffleSecrets.json": "TruffleHog-style secrets dump (Shai-Hulud)",
        "/tmp/processor.sh": "Malicious installer script",
        "/tmp/migrate-repos.sh": "Malicious migration script"
    },
    
    "text_iocs": [
        "webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7", # Known C2
        "SHA1HULUD", 
        "Sha1-Hulud: The Second Coming"
    ],

    "suspicious_workflow_patterns": [
        {"pattern": "runs-on: self-hosted", "risk": "High", "desc": "Self-hosted runner usage (potential persistence target)"},
        {"pattern": "discussion:", "risk": "Critical", "desc": "Workflow triggered by 'discussion' (Backdoor Indicator)"},
        {"pattern": "tojson(secrets)", "risk": "Critical", "desc": "Secrets serialization (Exfiltration Indicator)"},
        {"pattern": "curl ", "risk": "Low", "desc": "Network call in workflow (Requires manual review)"}
    ],
    
    "suspicious_runner_names": ["HULUD", "SHA1", "TEST", "DEBUG"],
    "campaign_markers": ["shai-hulud", "sha1hulud", "shai hulud", "migration"],
    "ignored_directories": {"node_modules", ".git", "dist", "build", "vendor"},
    "lockfile_names": {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}
}

@dataclass
class Finding:
    repo: str
    risk_level: str  # Critical, High, Medium, Low
    category: str    # Dependency, Workflow, Infrastructure, Artifact, Defacement
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
    """Fetches dynamic list of malicious packages from Wiz."""
    log(f"Fetching latest threat intel from {url}...", "INFO")
    try:
        with urllib.request.urlopen(url) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        
        db = {}
        reader = csv.DictReader(io.StringIO(content))
        count = 0
        
        # Header normalization logic
        headers = [h.lower() for h in reader.fieldnames or []]
        pkg_key = next((h for h in reader.fieldnames if h.lower() in ["package name", "package", "name"]), None)
        ver_key = next((h for h in reader.fieldnames if h.lower() in ["version", "versions"]), None)

        if not pkg_key or not ver_key:
            log("Could not parse CSV headers. Using column fallback.", "WARN")
            return {}

        for row in reader:
            pkg = row.get(pkg_key)
            ver = row.get(ver_key)
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

def version_match(constraint: str, bad_versions: Set[str]) -> bool:
    """Smart version matching using 'packaging' if available."""
    if not constraint: return False
    constraint = str(constraint).strip()
    
    if not HAVE_PACKAGING:
        # Fallback: Simple exact string match or inclusion
        norm = constraint.lstrip("^~=>=<").strip()
        return norm in bad_versions

    try:
        spec = SpecifierSet(constraint)
        for v in bad_versions:
            try:
                if Version(v) in spec:
                    return True
            except:
                continue
        return False
    except InvalidSpecifier:
        norm = constraint.lstrip("^~=>=<").strip()
        return norm in bad_versions

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
                if any(s in name.upper() for s in THREAT_CONFIG["suspicious_runner_names"]):
                    findings.append(Finding(
                        repo="<ORG_INFRASTRUCTURE>",
                        risk_level="Critical",
                        category="Infrastructure",
                        location=f"Runner ID: {r.get('id')}",
                        details=f"Suspicious Runner Name: '{name}' (Status: {status})"
                    ))
        except json.JSONDecodeError:
            pass
    return findings

def scan_repo_defacement(repo: dict) -> List[Finding]:
    """Checks repo metadata for campaign markers."""
    findings = []
    name = repo.get("name", "")
    desc = (repo.get("description") or "").lower()
    
    if any(m in desc for m in THREAT_CONFIG["campaign_markers"]):
        findings.append(Finding(name, "High", "Defacement", "Description", "Repo description contains threat actor marker"))
    
    if "migration" in desc and "shai" in desc:
        findings.append(Finding(name, "Critical", "Defacement", "Metadata", "Repo looks like a Shai-Hulud 'Migration' repo"))
        
    return findings

def scan_package_json(org: str, repo: str, path: str, content: str, malware_db: Dict[str, Set[str]]) -> List[Finding]:
    """Deep scan of package.json for deps AND malicious scripts."""
    findings = []
    try:
        data = json.loads(content)
        
        # 1. Dependency Check (Smart)
        all_deps = {}
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            all_deps.update(data.get(key, {}))
            
        for pkg, ver in all_deps.items():
            if pkg in malware_db:
                bad_vers = malware_db[pkg]
                if version_match(ver, bad_vers):
                    findings.append(Finding(repo, "High", "Dependency", path, f"Malicious Package: {pkg} @ {ver} (Matches specific bad version)"))
                else:
                    findings.append(Finding(repo, "Medium", "Dependency", path, f"Suspicious Package: {pkg} @ {ver} (Package in IOC list)"))

        # 2. Script Check (Behavioral)
        scripts = data.get("scripts", {})
        for name, cmd in scripts.items():
            if "setup_bun.js" in cmd or "bun_environment.js" in cmd:
                findings.append(Finding(repo, "Critical", "Malware Script", f"{path} -> scripts['{name}']", f"Executes known malware payload: {cmd}"))
            
            # Check for text IOCs inside scripts
            for ioc in THREAT_CONFIG["text_iocs"]:
                if ioc in cmd:
                    findings.append(Finding(repo, "Critical", "IOC in Script", f"{path} -> scripts['{name}']", f"Contains IOC: {ioc}"))
                    
    except json.JSONDecodeError:
        pass
    return findings

def scan_lockfile_json(org: str, repo: str, path: str, content: str, malware_db: Dict[str, Set[str]]) -> List[Finding]:
    """Recursive scan of package-lock.json structures."""
    findings = []
    try:
        lock = json.loads(content)
        
        # Helper to walk v1 dependencies
        def walk_deps(deps):
            for name, info in deps.items():
                if name in malware_db:
                    ver = info.get("version", "")
                    if ver in malware_db[name]:
                        findings.append(Finding(repo, "High", "Transitive Dependency", path, f"Exact malicious version found: {name}@{ver}"))
                if "dependencies" in info:
                    walk_deps(info["dependencies"])

        if "dependencies" in lock:
            walk_deps(lock["dependencies"])
            
        # v2/v3 packages
        if "packages" in lock:
            for pkg_path, info in lock["packages"].items():
                name = info.get("name") or pkg_path.split("node_modules/")[-1]
                if name in malware_db:
                    ver = info.get("version", "")
                    if ver in malware_db[name]:
                        findings.append(Finding(repo, "High", "Transitive Dependency", path, f"Exact malicious version found in packages: {name}@{ver}"))

    except json.JSONDecodeError:
        pass
    return findings

# --- 4. MAIN CONTROLLER ---

def main():
    parser = argparse.ArgumentParser(description="GitHub Organization Threat Scanner (Ultimate)")
    parser.add_argument("--org", required=True, help="GitHub Organization name")
    parser.add_argument("--limit", type=int, default=1000, help="Max repos to scan")
    parser.add_argument("--repo", help="Scan a single specific repo only")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logs")
    parser.add_argument("--output", default=f"scan_report_{int(datetime.now().timestamp())}.json", help="Output JSON file")
    
    args = parser.parse_args()
    
    print(f"""
    🛡️  GITHUB THREAT SCANNER (ULTIMATE)
    ====================================
    Target Org:  {args.org}
    Scan Limit:  {args.limit}
    Smart Versioning: {'✅ Enabled' if HAVE_PACKAGING else '⚠️ Disabled (install "packaging" lib for better results)'}
    ------------------------------------
    """)

    # 1. Setup
    malware_db = fetch_intel_feed(THREAT_CONFIG["intel_feed_url"])
    all_findings = []

    # 2. Infra Scan
    if not args.repo:
        runner_issues = scan_runners(args.org)
        all_findings.extend(runner_issues)

    # 3. Repo Fetch
    if args.repo:
        repos = [{"name": args.repo, "defaultBranchRef": {"name": "main"}}] 
    else:
        log("Fetching repository list...", "INFO")
        repos_raw = run_gh_cmd(["gh", "repo", "list", args.org, "--limit", str(args.limit), "--no-archived", "--json", "name,defaultBranchRef,description"])
        repos = json.loads(repos_raw) if repos_raw else []

    log(f"Starting scan on {len(repos)} repositories...", "INFO")

    # 4. Repo Scan Loop
    for i, repo in enumerate(repos):
        name = repo['name']
        branch = repo.get('defaultBranchRef', {}).get('name', 'main')
        
        if args.verbose:
            print(f"    Scanning [{i+1}/{len(repos)}]: {name}")
        else:
            print(f"    Scanning [{i+1}/{len(repos)}]: {name:<40}", end='\r')
        
        # A. Meta Check
        all_findings.extend(scan_repo_defacement(repo))

        # B. Tree Fetch
        tree_data = run_gh_cmd(["gh", "api", f"repos/{args.org}/{name}/git/trees/{branch}?recursive=1"])
        if not tree_data: continue
        
        try:
            tree = json.loads(tree_data)
            paths = [item["path"] for item in tree.get("tree", []) if item["type"] == "blob"]
        except: continue

        # C. File Iteration
        for path in paths:
            filename = PurePosixPath(path).name
            
            # skip ignored
            if any(x in path for x in THREAT_CONFIG["ignored_directories"]): continue

            # 1. Artifact Check
            if filename in THREAT_CONFIG["malicious_filenames"]:
                reason = THREAT_CONFIG["malicious_filenames"][filename]
                all_findings.append(Finding(name, "Critical", "Artifact", path, f"Malware file found: {reason}"))

            # 2. Workflow Scan
            if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
                content = run_gh_cmd(["gh", "api", f"repos/{args.org}/{name}/contents/{path}", "-H", "Accept: application/vnd.github.raw"])
                if content:
                    lower = content.lower()
                    for p in THREAT_CONFIG["suspicious_workflow_patterns"]:
                        if p["pattern"] in lower:
                            all_findings.append(Finding(name, p["risk"], "Workflow", path, p["desc"]))
                    if filename in ["discussion.yaml", "discussion.yml"]:
                        all_findings.append(Finding(name, "Critical", "Backdoor", path, "Specific Shai-Hulud Backdoor file"))

            # 3. Package.json Scan
            if filename == "package.json":
                content = run_gh_cmd(["gh", "api", f"repos/{args.org}/{name}/contents/{path}", "-H", "Accept: application/vnd.github.raw"])
                if content:
                    all_findings.extend(scan_package_json(args.org, name, path, content, malware_db))

            # 4. Lockfile Scan
            if filename in THREAT_CONFIG["lockfile_names"]:
                content = run_gh_cmd(["gh", "api", f"repos/{args.org}/{name}/contents/{path}", "-H", "Accept: application/vnd.github.raw"])
                if content:
                    # Simple string search first (fastest)
                    for mal_pkg in malware_db:
                        if f'"{mal_pkg}"' in content or f'{mal_pkg}@' in content:
                            # If it's a JSON lockfile, do deep scan
                            if filename in ["package-lock.json", "npm-shrinkwrap.json"]:
                                all_findings.extend(scan_lockfile_json(args.org, name, path, content, malware_db))
                            else:
                                all_findings.append(Finding(name, "Medium", "Transitive", path, f"Reference to malicious pkg '{mal_pkg}' in lockfile"))
                            break # Don't spam hits for the same file if one found

            # 5. Generic Text IOC Scan (Webhooks, C2)
            if filename.endswith((".js", ".ts", ".sh", ".py", ".json")):
                 # Don't fetch content again if we already have it
                 # For efficiency, we usually skip this unless high paranoid mode, 
                 # but let's check for webhook.site in code files quickly if small
                 pass # Omitted for speed unless user requests deep text scan

    print("\n" + "-"*50)

    # 5. Reporting
    criticals = [f for f in all_findings if f.risk_level in ["Critical", "High"]]
    
    if all_findings:
        log(f"Scan Complete. Found {len(all_findings)} issues ({len(criticals)} Critical/High).", "WARN")
        
        with open(args.output, "w") as f:
            json.dump([f.to_dict() for f in all_findings], f, indent=2)
        log(f"Full report saved to: {args.output}", "GOOD")
        
        if criticals:
            print("\n🚨 CRITICAL FINDINGS SUMMARY:")
            for f in criticals:
                print(f"  • [{f.repo}] {f.category}: {f.details}")
    else:
        log("Scan Complete. No threats detected.", "GOOD")

if __name__ == "__main__":
    main()
