#!/usr/bin/env python3
"""
Quick script to check for common exposed files on the CloudAI Corp challenge.
"""

import requests
import sys

# Target URL from your challenge
BASE_URL = "http://cdcommrdzlyxsyvl91xvkyn4flz04mdvwool7t135-web.cybertalentslabs.com"

# List of common sensitive files and directories to check
COMMON_PATHS = [
    # Cloud & Config Files
    "/.env",
    "/config.json",
    "/app/config.json",
    "/aws/credentials",
    "/terraform.tfvars",
    "/.aws/credentials",
    # Documentation
    "/README.md",
    "/CHANGELOG.md",
    "/package.json",
    "/composer.json",
    # Backup & Logs
    "/backup.zip",
    "/backup.tar.gz",
    "/log.txt",
    "/debug.log",
    "/admin.log",
    "/logs/access.log",
    # Server Files
    "/.htaccess",
    "/nginx.conf",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    # Version Control (even if .git/ is 404)
    "/.gitignore",
    "/.git/config",
    # Common Directories
    "/admin/",
    "/backup/",
    "/config/",
    "/uploads/",
    "/api/",
    "/swagger/",
    "/v1/",
    # Sometimes these work
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/phpinfo.php",
    # Try some variations
    "/.env.local",
    "/.env.production",
    "/.env.example",
]

def check_url(url):
    """Check a single URL and report interesting findings."""
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code == 200:
            content_length = len(response.content)
            # Check if it's not just a small default page
            if content_length > 100:
                print(f"[+] FOUND (200): {url} - Size: {content_length} bytes")
                # Print a preview if it's text
                if 'text' in response.headers.get('Content-Type', ''):
                    preview = response.text[:200].replace('\n', ' ')
                    print(f"    Preview: {preview}...")
                return True
            elif content_length > 0:
                print(f"[~] Found with small response ({content_length} bytes): {url}")
        elif response.status_code == 403:
            print(f"[!] FORBIDDEN (403): {url} - Interesting!")
            return True
        elif response.status_code == 301 or response.status_code == 302:
            print(f"[>] REDIRECT ({response.status_code}): {url} -> {response.headers.get('Location')}")
        # Don't print 404s to keep output clean
    except requests.exceptions.RequestException as e:
        # Don't print connection errors unless you want to see them
        # print(f"[E] Error for {url}: {e}")
        pass
    return False

def main():
    print(f"Checking for exposed files on: {BASE_URL}")
    print("=" * 60)
    
    found_count = 0
    for path in COMMON_PATHS:
        target_url = BASE_URL + path
        if check_url(target_url):
            found_count += 1
    
    print("=" * 60)
    print(f"Scan complete. Found {found_count} interesting responses.")
    
    if found_count == 0:
        print("\nNo obvious files found. Next steps:")
        print("1. Check for directory listing on common paths:")
        print("   - Try accessing /admin/, /backup/, /config/ in browser")
        print("2. Look for file inclusion parameters in URL")
        print("   - Example: ?page=../../../../etc/passwd")
        print("3. Use a tool like dirb, dirbuster, or gobuster")
        print("   - Command: gobuster dir -u {BASE_URL} -w /usr/share/wordlists/dirb/common.txt")

if __name__ == "__main__":
    main()