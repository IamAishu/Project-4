import requests
import re
import socket

try:
    import nmap  # Requires Nmap to be installed
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Function to check if the URL is valid and formatted correctly
def validate_url(target_url):
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url  # Default to HTTPS
    return target_url

# Function to check for XSS vulnerability
def check_xss(target_url):
    target_url = validate_url(target_url)
    test_url = target_url + "?q=<script>alert('XSS')</script>"
    
    try:
        response = requests.get(test_url, timeout=5)

        if "<script>alert('XSS')</script>" in response.text:
            print(f"[⚠️] Potential XSS vulnerability found at: {test_url}")
        else:
            print(f"[✅] No XSS vulnerability detected at: {test_url}")

    except requests.exceptions.RequestException as e:
        print(f"[❌] Error checking XSS: {e}")

# Function to check for SQL Injection vulnerability
def check_sql_injection(target_url):
    target_url = validate_url(target_url)
    test_url = target_url + "?id=1' OR '1'='1"
    
    try:
        response = requests.get(test_url, timeout=5)

        error_patterns = [
            "You have an error in your SQL syntax;",
            "Warning: mysql_fetch_array()",
            "Unclosed quotation mark after the character string",
            "Microsoft OLE DB Provider for SQL Server",
        ]

        if any(error in response.text for error in error_patterns):
            print(f"[⚠️] Potential SQL Injection vulnerability found at: {test_url}")
        else:
            print(f"[✅] No SQL Injection vulnerability detected at: {test_url}")

    except requests.exceptions.RequestException as e:
        print(f"[❌] Error checking SQL Injection: {e}")

# Function to scan open ports using Nmap
def scan_open_ports(target_url):
    if not NMAP_AVAILABLE:
        print("[❌] Nmap is not installed. Skipping port scan.")
        return

    target_url = target_url.replace("https://", "").replace("http://", "").split('/')[0]
    
    nm = nmap.PortScanner()
    try:
        print(f"[*] Scanning open ports on {target_url}...")
        nm.scan(target_url, '20-1000')

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"[⚠️] Open Port Found: {port}/{proto} on {host}")

    except Exception as e:
        print(f"[❌] Error scanning ports: {e}")

# Function to check security headers
def check_security_headers(target_url):
    target_url = validate_url(target_url)

    try:
        response = requests.get(target_url, timeout=5)
        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        print("\n[*] Checking Security Headers:")
        for header in security_headers:
            if header in headers:
                print(f"[✅] {header}: {headers[header]}")
            else:
                print(f"[⚠️] Missing Security Header: {header}")

    except requests.exceptions.RequestException as e:
        print(f"[❌] Error checking security headers: {e}")

# Main function to run all checks
if __name__ == "__main__":
    target_url = input("Enter website URL to scan: ").strip()

    check_xss(target_url)
    check_sql_injection(target_url)
    scan_open_ports(target_url)
    check_security_headers(target_url)
