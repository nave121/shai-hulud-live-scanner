import subprocess
import json
import sys
import urllib.request
import csv
import io

# Usage: python3 shai_hulud_scanner.py <YOUR_ORG_NAME>
# Example: python3 shai_hulud_scanner.py Navina-ai

# Source of Truth: Wiz Research Public IOCs
WIZ_IOC_URL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"

def fetch_live_malicious_list(url):
    """Fetches the latest CSV from Wiz's GitHub repo."""
    print(f"🌐 Connecting to Wiz Research IOCs...")
    try:
        with urllib.request.urlopen(url) as response:
            csv_content = response.read().decode('utf-8')
            
        db = {}
        reader = csv.DictReader(io.StringIO(csv_content))
        
        for row in reader:
            # Handles varying CSV header names if Wiz changes them
            pkg = row.get('Package Name') or row.get('Package')
            ver = row.get('Version')
            
            if pkg and ver:
                clean_vers = ver.replace('=', '').replace('||', ' ').split()
                db[pkg] = clean_vers
                
        print(f"✅ Loaded {len(db)} malicious packages from live source.")
        return db
    except Exception as e:
        print(f"❌ Error fetching live list: {e}")
        sys.exit(1)

def get_all_repos(org):
    """Fetches all repos in the org using GitHub CLI."""
    print(f"🔄 Fetching repository list for {org}...")
    cmd = ["gh", "repo", "list", org, "--limit", "2000", "--json", "name", "--no-archived"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Error fetching repos. Ensure 'gh' CLI is installed and authenticated.")
        sys.exit(1)
    return json.loads(result.stdout)

def check_repo(org, repo_name, malicious_db):
    """Fetches package.json via API and checks dependencies."""
    cmd = [
        "gh", "api", 
        f"repos/{org}/{repo_name}/contents/package.json", 
        "-H", "Accept: application/vnd.github.raw"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
        dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        
        found = []
        for pkg, ver_constraint in dependencies.items():
            if pkg in malicious_db:
                bad_versions = malicious_db[pkg]
                found.append(f"⚠️  {pkg} (Current: {ver_constraint} | Malicious Variants: {bad_versions})")
        return found
    except:
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 shai_hulud_scanner.py <ORG_NAME>")
        sys.exit(1)
        
    org_name = sys.argv[1]
    
    print(f"🚀 Starting Live Shai-Hulud 2.0 Scan for: {org_name}")
    print("="*50)
    
    malware_db = fetch_live_malicious_list(WIZ_IOC_URL)
    repos = get_all_repos(org_name)
    print(f"🔎 Scanning {len(repos)} repositories against live data...")
    
    infected_repos = {}

    for i, repo in enumerate(repos):
        name = repo['name']
        print(f"[{i+1}/{len(repos)}] Checking {name}...", end='\r')
        
        hits = check_repo(org_name, name, malware_db)
        if hits:
            infected_repos[name] = hits

    print("\n" + "="*50)
    if infected_repos:
        print(f"🚨 POTENTIAL MATCHES FOUND IN {len(infected_repos)} REPOSITORIES:")
        for repo, hits in infected_repos.items():
            print(f"\n📂 Repo: {repo}")
            for hit in hits:
                print(f"   {hit}")
    else:
        print("🟢 CLEAN: No malicious package names found in any package.json.")
    print("="*50)
