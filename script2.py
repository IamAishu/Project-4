import requests
import nmap
import socket
import json
from bs4 import BeautifulSoup
from flask import Flask, render_template, request
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

def get_ip(url):
    try:
        return socket.gethostbyname(url)
    except socket.gaierror:
        return "Unable to resolve IP"

def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        if payload in response.text:
            return "Possible XSS vulnerability found!"
    except requests.exceptions.RequestException:
        return "Error checking XSS"
    return "No XSS detected"

def check_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        error_messages = ["mysql", "syntax error", "SQL", "database"]
        for error in error_messages:
            if error.lower() in response.text.lower():
                return "Possible SQL Injection vulnerability found!"
    except requests.exceptions.RequestException:
        return "Error checking SQL Injection"
    return "No SQL Injection detected"

def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-p 1-65535 -sV')

    if ip in scanner.all_hosts():
        results = {}
        if 'tcp' in scanner[ip]:
            results['tcp'] = list(scanner[ip]['tcp'].keys())
        if 'udp' in scanner[ip]:
            results['udp'] = list(scanner[ip]['udp'].keys())
        return results
    else:
        return {"error": "No results found for the given IP"}
def generate_pdf_report(url, results):
    filename = f"{url.replace('://', '_').replace('/', '_')}_scan_report.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(30, 750, f"Security Scan Report for {url}")
    c.setFont("Helvetica", 12)
    c.drawString(30, 730, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(30, 710, f"IP Address: {results['ip']}")
    y = 680
    
    for section, data in results.items():
        if isinstance(data, list):
            c.setFont("Helvetica-Bold", 12)
            c.drawString(30, y, section.replace('_', ' ').title())
            y -= 20
            c.setFont("Helvetica", 10)
            for item in data:
                c.drawString(40, y, f"- {item}")
                y -= 15
            y -= 10
    
    c.save()
    return filename

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith("http"):
            url = "http://" + url
        
        ip = get_ip(url.split('//')[1])
        headers = requests.get(url).headers
        xss_result = check_xss(url)
        sql_result = check_sql_injection(url)
        ports_result = scan_ports(ip)
        
        results = {
            "ip": ip,
            "headers": [f"{key}: {value}" for key, value in headers.items()],
            "xss_vulnerability": [xss_result],
            "sql_injection": [sql_result],
            "open_ports": ports_result
        }
        
        pdf_file = generate_pdf_report(url, results)
        return render_template("index.html", results=results, pdf_file=pdf_file)
    
    return render_template("index.html", results=None)

if __name__ == '__main__':
    app.run(debug=True)
