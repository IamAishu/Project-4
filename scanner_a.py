import requests
import socket
import nmap
import json
from bs4 import BeautifulSoup
from colorama import Fore, Style

# Function to resolve the IP address of a given URL
def get_ip(url):
    try:
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error resolving IP: {e}"

# Function to scan for open ports using nmap
def scan_ports(ip):
    try:
        scanner = nmap.PortScanner()
        print(Fore.YELLOW + f"⏳ Running quick port scan on {ip}..." + Style.RESET_ALL)

        # Perform a fast scan (-T4 for speed, -F to scan common ports)
        scanner.scan(ip, arguments="-T4 -F")

        open_ports = []
        if ip in scanner.all_hosts():
            for proto in scanner[ip].all_protocols():
                for port in scanner[ip][proto]:
                    open_ports.append(f"Port {port}: {scanner[ip][proto][port]['name']} ({scanner[ip][proto][port]['state']})")

        return open_ports if open_ports else ["No open ports found"]
    
    except nmap.PortScannerError as e:
        return [f"❌ Nmap scan failed: {e}"]
    except Exception as e:
        return [f"⚠️ Unexpected error: {e}"]

# Function to check for multiple XSS vulnerabilities
def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "javascript:alert('XSS')"
    ]
    results = []
    for payload in payloads:
        try:
            response = requests.get(url + "?q=" + payload, timeout=5)
            if payload in response.text:
                results.append(f"⚠️ XSS detected with payload: {payload}")
        except Exception as e:
            results.append(f"XSS test failed: {e}")

    return results if results else ["No XSS vulnerabilities found."]

# Function to check for multiple SQL injection vulnerabilities
def check_sql_injection(url):
    payloads = [
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1\" --",
        "admin' --",
        "' UNION SELECT null, version() --"
    ]
    results = []
    for payload in payloads:
        try:
            response = requests.get(url + "?id=" + payload, timeout=5)
            if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                results.append(f"⚠️ SQL Injection detected with payload: {payload}")
        except Exception as e:
            results.append(f"SQL Injection test failed: {e}")

    return results if results else ["No SQL Injection vulnerabilities found."]

# Function to enumerate hidden directories
def check_directories(url):
    common_dirs = ["admin", "login", "backup", "test", "old", "private"]
    found_dirs = []
    for d in common_dirs:
        full_url = f"{url}/{d}"
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                found_dirs.append(f"📂 Found directory: {full_url}")
        except Exception:
            continue
    
    return found_dirs if found_dirs else ["No sensitive directories found."]

# Function to analyze security headers
def check_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = ["X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]
        missing_headers = [h for h in security_headers if h not in headers]

        if missing_headers:
            return [f"⚠️ Missing security headers: {', '.join(missing_headers)}"]
        return ["✅ All recommended security headers are present."]
    except Exception as e:
        return [f"Header analysis failed: {e}"]

# Function to detect CMS (WordPress, Joomla, etc.)
def detect_cms(url):
    try:
        response = requests.get(url, timeout=5)
        if "wp-content" in response.text:
            return "🟢 WordPress detected!"
        elif "Joomla" in response.text:
            return "🟠 Joomla detected!"
        return "🔵 No CMS detected."
    except Exception as e:
        return f"CMS detection failed: {e}"

# Function to save results to a text file
def save_results(url, results):
    filename = url.replace("http://", "").replace("https://", "").split('/')[0] + "_scan_report.txt"
    with open(filename, "w", encoding="utf-8") as file:
        file.write(json.dumps(results, indent=4))
    print(Fore.GREEN + f"\n✅ Scan report saved as {filename}" + Style.RESET_ALL)

# Main function to run all tests
def run_scanner(target_url):
    print(Fore.YELLOW + "\n🔍 Running Advanced Vulnerability Scanner on:", target_url + Style.RESET_ALL)
    
    ip = get_ip(target_url)
    print(Fore.CYAN + f"🌍 Resolved IP: {ip}" + Style.RESET_ALL)

    results = {"Target": target_url, "IP": ip, "Results": {}}

    if "Error" not in ip:
        print(Fore.MAGENTA + "\n📡 Scanning Open Ports..." + Style.RESET_ALL)
        ports = scan_ports(ip)
        results["Results"]["Open Ports"] = ports
        for p in ports:
            print(f"  - {p}")

    print(Fore.MAGENTA + "\n🛡️ Checking for XSS Vulnerabilities..." + Style.RESET_ALL)
    xss_results = check_xss(target_url)
    results["Results"]["XSS Vulnerabilities"] = xss_results
    for res in xss_results:
        print(f"  ➜ {res}")

    print(Fore.MAGENTA + "\n🔓 Checking for SQL Injection Vulnerabilities..." + Style.RESET_ALL)
    sql_results = check_sql_injection(target_url)
    results["Results"]["SQL Injection"] = sql_results
    for res in sql_results:
        print(f"  ➜ {res}")

    print(Fore.MAGENTA + "\n📂 Checking for Hidden Directories..." + Style.RESET_ALL)
    dir_results = check_directories(target_url)
    results["Results"]["Hidden Directories"] = dir_results
    for res in dir_results:
        print(f"  ➜ {res}")

    print(Fore.MAGENTA + "\n🔎 Analyzing HTTP Security Headers..." + Style.RESET_ALL)
    header_results = check_headers(target_url)
    results["Results"]["Security Headers"] = header_results
    for res in header_results:
        print(f"  ➜ {res}")

    print(Fore.MAGENTA + "\n🖥️ Detecting CMS..." + Style.RESET_ALL)
    cms_result = detect_cms(target_url)
    results["Results"]["CMS Detection"] = [cms_result]
    print(f"  ➜ {cms_result}")

    save_results(target_url, results)

# Entry point for the script
if __name__ == "__main__":
    target = input(Fore.CYAN + "Enter the target website URL (e.g., https://example.com): " + Style.RESET_ALL)
    run_scanner(target)
