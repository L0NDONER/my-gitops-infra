#!/usr/bin/env python3
"""
Secret Scanner - Git Pre-Commit Hook
Prevents accidental commit of unencrypted secrets to version control

Version History:
0.1 - Initial keyword scanning
0.2 - Added Jinja2 template detection
0.3 - Added hash/file path exclusions
0.4 - Added exit code for git hook integration
0.5 - Added gitignored file exclusions and env var pattern detection

Usage:
  python3 secret_scan.py           # Scan and report
  echo $?                          # Check exit code (0=clean, 1=secrets found)
"""
import os
import re
import sys
import subprocess

# Sensitive patterns to look for
SENSITIVE_KEYWORDS = ['password', 'token', 'secret', 'api_key', 'sid', 'auth', 'become_pass']

# Files/patterns to exclude (gitignored or intentionally safe)
EXCLUDED_FILES = [
    'secrets.py',      # Gitignored local secrets file
    '.vault_pass',     # Ansible vault password
]

EXCLUDED_DIRS = [
    '.git',
    '__pycache__',
    'group_vars',      # Already encrypted with vault
]

def is_gitignored(filepath, base_path):
    """Check if file is gitignored using git check-ignore"""
    try:
        result = subprocess.run(
            ['git', 'check-ignore', filepath],
            cwd=base_path,
            capture_output=True,
            timeout=1
        )
        return result.returncode == 0  # Returns 0 if file is ignored
    except:
        return False

def is_safe_pattern(line):
    """Check if line contains safe patterns that aren't actual secrets"""
    safe_patterns = [
        r'os\.getenv\(',           # Environment variable loading
        r'from\s+\.secrets\s+import',  # Importing from gitignored file
        r'import\s+.*secrets',     # Importing secrets module
        r'requests\.get\(.*auth=\(',  # requests.get with auth tuple
        r'api_key=config\.',       # Loading API key from config
        r'max_tokens=',            # API parameter, not a secret
    ]
    return any(re.search(pattern, line) for pattern in safe_patterns)

def scan_dry_run():
    base_path = os.path.expanduser("~/ansible")
    print(f"🕵️  SCANNING: Checking {base_path} for unencrypted secrets...")
    
    found_count = 0
    flagged_files = set()
    
    for root, dirs, files in os.walk(base_path):
        # Skip excluded directories
        if any(excluded in root for excluded in EXCLUDED_DIRS):
            continue
        
        for file in files:
            # Skip excluded files
            if file in EXCLUDED_FILES:
                continue
            
            # Skip documentation files
            if file.endswith((".md", ".txt", "README")):
                continue
            
            file_path = os.path.join(root, file)
            
            # Skip gitignored files
            if is_gitignored(file_path, base_path):
                continue
            
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    lines = f.readlines()
                    
                    # 1. Skip files already encrypted with Ansible Vault
                    content = ''.join(lines)
                    if "$ANSIBLE_VAULT;" in content: 
                        continue
                    
                    for line_num, line in enumerate(lines, 1):
                        # Skip comments
                        stripped = line.strip()
                        if stripped.startswith('#'):
                            continue
                        
                        # Skip safe patterns (env vars, imports from gitignored files)
                        if is_safe_pattern(line):
                            continue
                        
                        # Skip YAML list items that are quoted strings (display messages)
                        if re.match(r'^\s*-\s*["\']', stripped):
                            continue
                        
                        for key in SENSITIVE_KEYWORDS:
                            # Match patterns like:
                            #   password: value
                            #   my_password: value  
                            #   password_file: value
                            # But NOT:
                            #   wireguard_password_hash: {{ vault_var }}
                            #   some_other_password_thing: {{ vault_var }}
                            
                            # Look for the keyword with optional prefix/suffix but check if value is templated
                            pattern = fr'\w*{key}\w*\s*[:=]\s*(.+)'
                            
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                full_match = match.group(0)
                                value = match.group(1).strip()
                                
                                # Skip if the value contains Jinja2 template syntax
                                if '{{' in value or '}}' in value:
                                    continue
                                
                                # Skip if this looks like a hash/encoded version (ends with _hash, _encrypted, etc)
                                if re.search(r'_(hash|encrypted|vault|encoded)\s*[:=]', full_match, re.IGNORECASE):
                                    continue
                                
                                # Skip if this is a file path reference (ends with _file)
                                if re.search(r'_file\s*[:=]', full_match, re.IGNORECASE):
                                    continue
                                    
                                print(f"🚩 FLAG: {file_path}:{line_num}")
                                print(f"   Keyword: {key}")
                                print(f"   Line: {line.strip()}")
                                print()
                                found_count += 1
                                flagged_files.add(file_path)
                                break
            except: 
                continue
    
    print(f"\n{'='*60}")
    if found_count > 0:
        print(f"❌ SCAN FAILED: Found {found_count} potential secret(s) in {len(flagged_files)} file(s)")
        print(f"\nRecommendations:")
        print(f"  1. Move secrets to group_vars/all.yml")
        print(f"  2. Encrypt: ansible-vault encrypt group_vars/all.yml")
        print(f"  3. Reference in playbooks: {{{{ vault_variable_name }}}}")
        print(f"{'='*60}\n")
        return 1  # Exit code 1 = secrets found
    else:
        print(f"✅ SCAN PASSED: No unencrypted secrets detected")
        print(f"{'='*60}\n")
        return 0  # Exit code 0 = clean

if __name__ == "__main__":
    exit_code = scan_dry_run()
    sys.exit(exit_code)
