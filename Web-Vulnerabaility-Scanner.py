
import requests
from bs4 import BeautifulSoup
import nmap
import logging
import re
import aiohttp
import asyncio
from urllib.parse import urlparse

# ✅ Corrected logging format
logging.basicConfig(
    filename='scan_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def is_valid_url(url):
    pattern = re.compile(r'^(https?://)?(www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(pattern.match(url))

async def fetch(session, url):
    try:
        async with session.get(url, timeout=15, allow_redirects=True) as response:
            response.raise_for_status()
            logging.info(f"Successfully fetched {url}")
            return await response.text()
    except aiohttp.ClientError as e:
        logging.error(f"Error fetching {url}: {e}")
        return None
    except asyncio.TimeoutError:
        logging.error(f"Timeout while fetching {url}")
        return None

async def scan_web_application(url, user_agent):
    if not is_valid_url(url):
        logging.error("Invalid URL format.")
        return None

    headers = {'User-Agent': user_agent}
    async with aiohttp.ClientSession(headers=headers) as session:
        html_content = await fetch(session, url)
        if html_content:
            logging.info("Website is reachable.")
            return html_content
        return None

def check_vulnerabilities(url, user_agent):
    results = {
        "sql_injection": False,
        "xss": False,
        "rce": False,
        "command_injection": False,
        "directory_traversal": False,
        "insecure_deserialization": False
    }

    payloads = {
        "sql_injection": ["'", "' OR '1'='1"],
        "xss": "<script>alert('XSS')</script>",
        "directory_traversal": "../../../../../etc/passwd"
    }
    
    vulnerable_endpoint = "/listproducts.php?cat="
    xss_endpoint = "/artists.php?artist="

    headers = {'User-Agent': user_agent}

    # Test for SQL Injection
    for payload in payloads["sql_injection"]:
        test_url = f"{url}{vulnerable_endpoint}{payload}"
        try:
            logging.info(f"Testing SQL Injection with URL: {test_url}")
            response = requests.get(test_url, headers=headers, timeout=10)
            if response.ok and "query error" in response.text.lower():
                logging.info(f"Potential SQL Injection found at {test_url}")
                results["sql_injection"] = True
                break
        except requests.RequestException as e:
            logging.error(f"Error checking SQL injection: {e}")

    # Test for XSS
    xss_test_url = f"{url}{xss_endpoint}{payloads['xss']}"
    try:
        logging.info(f"Testing XSS with URL: {xss_test_url}")
        response = requests.get(xss_test_url, headers=headers, timeout=10)
        if response.ok and payloads['xss'] in response.text:
            logging.info(f"Potential XSS found at {xss_test_url}")
            results["xss"] = True
    except requests.RequestException as e:
        logging.error(f"Error checking XSS: {e}")

    # Test for Directory Traversal
    dt_test_url = f"{url}{vulnerable_endpoint}{payloads['directory_traversal']}"
    try:
        logging.info(f"Testing Directory Traversal with URL: {dt_test_url}")
        response = requests.get(dt_test_url, headers=headers, timeout=10)
        if response.ok and "root:" in response.text:
            logging.info("Potential Directory Traversal found.")
            results["directory_traversal"] = True
    except requests.RequestException as e:
        logging.error(f"Error checking Directory Traversal: {e}")

    return results
def scan_ports(host):
    try:
        nm = nmap.PortScanner()
        logging.info(f"Scanning ports for {host}...")
        nm.scan(host, '80,443')
        
        open_ports = []
        if host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        return open_ports
    except nmap.PortScannerError as e:
        logging.error(f"Nmap error: {e}")
        return []
    except Exception as e:
        logging.error(f"Error scanning ports: {e}")
        return []

def generate_report(url, vulnerabilities, open_ports):
    report = "\n--- Security Scan Report ---\n"
    report += f"URL: {url}\n"
    report += "--- Vulnerabilities ---\n"
    report += f"Potential SQL Injection: {'Found' if vulnerabilities['sql_injection'] else 'Not Found'}\n"
    report += f"Potential XSS: {'Found' if vulnerabilities['xss'] else 'Not Found'}\n"
    report += f"Potential RCE: {'Found' if vulnerabilities['rce'] else 'Not Found'}\n"
    report += f"Potential Command Injection: {'Found' if vulnerabilities['command_injection'] else 'Not Found'}\n"
    report += f"Potential Directory Traversal: {'Found' if vulnerabilities['directory_traversal'] else 'Not Found'}\n"
    report += f"Potential Insecure Deserialization: {'Found' if vulnerabilities['insecure_deserialization'] else 'Not Found'}\n"
    report += "--- Open Ports ---\n"
    report += "Open Ports: " + (", ".join(map(str, sorted(open_ports))) if open_ports else "None") + "\n"
    report += "----------------------------\n"

    print(report)

    with open("scan_report.txt", "w") as file:
        file.write(report)

def main():
    url = input("Enter the URL to scan (e.g., http://localhost:3000): ")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    user_agent = input("Enter User-Agent string (leave blank for default): ")
    if not user_agent:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112 Safari/537.36"

    logging.info(f"Starting scan for {url}...")
    html_content = asyncio.run(scan_web_application(url, user_agent))
    
    if html_content:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            vulnerabilities = check_vulnerabilities(url, user_agent)
            open_ports = scan_ports(hostname)
            generate_report(url, vulnerabilities, open_ports)
        else:
            logging.error("Could not extract a valid hostname from the URL.")
            print("Scan failed. Could not extract a valid hostname from the URL.")
    else:
        print("Scan failed. Could not reach the target URL.")

if name == "main":
    main()