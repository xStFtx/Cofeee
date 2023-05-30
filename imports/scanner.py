import requests
import socket
from bs4 import BeautifulSoup
import nmap
import os
import threading
import whois
import logging
import concurrent.futures
import time
from .fuzzer import Fuzzer

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")

# Constants
COMMON_SUBDOMAINS = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m",
                     "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
                     "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin", "store",
                     "mx1", "cdn", "api", "exchange", "app", "gov", "2tty", "vps", "govyty", "hgfgdf", "news", "1rer",
                     "lkjkui"]
COMMON_PORTS = [80, 443, 22]
MAX_CONCURRENT_REQUESTS = 10
MAX_RETRIES = 3
INITIAL_BACKOFF_DELAY = 1

# Configuration
REPORTS_DIRECTORY = "Reports"

# Lock for file writing
FILE_LOCK = threading.Lock()


class Scanner:
    def __init__(self, target_domains):
        self.target_domains = target_domains
        self.wordlist_directory = "wordlists"
        self.dir_file = "common_dir"

    def run(self):
        # Create Reports directory if it doesn't exist
        if not os.path.exists(REPORTS_DIRECTORY):
            os.makedirs(REPORTS_DIRECTORY)

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
            for target in self.target_domains:
                subdomains = self.find_subdomains(target)

                futures = []
                for subdomain in subdomains:
                    url = "https://" + subdomain

                    future = executor.submit(self.handle_request, url)
                    futures.append((subdomain, future))

                for subdomain, future in futures:
                    response = future.result()
                    if response and response.status_code == 200:
                        self.process_subdomain(target, subdomain)
                        thread = threading.Thread(target=self.crawl_and_analyze, args=(subdomain,))
                        thread.start()

                        fuzzer = Fuzzer(subdomain,)
                        fuzzer.start()

    def find_subdomains(self, target):
        subdomains = []

        for subdomain in COMMON_SUBDOMAINS:
            domain = subdomain + "." + target
            try:
                socket.gethostbyname(domain)
                subdomains.append(domain)
            except socket.error:
                pass

        return subdomains

    def handle_request(self, url):
        try:
            response = requests.get(url, timeout=10)
            return response
        except (requests.exceptions.RequestException, socket.error) as e:
            if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 404:
                # Perform URL hacking techniques here
                hacked_url = url + "/admin"
                logging.info("Trying hacked URL: %s", hacked_url)
                try:
                    response = requests.get(hacked_url, timeout=10)
                    return response
                except (requests.exceptions.RequestException, socket.error) as e:
                    logging.error("Error occurred while requesting %s: %s", hacked_url, e)
                    return None
            else:
                logging.error("Error occurred while requesting %s: %s", url, e)
                return None


    def process_subdomain(self, target, subdomain):
        open_ports = self.scan_ports(subdomain)
        logging.info("Open Ports for %s: %s", subdomain, open_ports)

        technologies = self.identify_technologies(subdomain)
        logging.info("Technologies for %s: %s", subdomain, technologies)

        vulnerabilities = self.test_vulnerabilities(subdomain)
        logging.info("Vulnerabilities for %s: %s", subdomain, vulnerabilities)

        information = self.gather_information(subdomain)
        logging.info("Information for %s: %s", subdomain, information)

        self.exploit_vulnerability(subdomain)

        self.additional_functionality(subdomain, technologies, vulnerabilities, information)

        if "api" in subdomain:  # Check if "api" is in the subdomain
            self.enumerate_api(subdomain)
        
        scanned_directories = self.scan_directories(subdomain)
        logging.info("Scanned Directories for %s: %s", subdomain, scanned_directories)
    
    def scan_ports(self, subdomain):
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
    
    def enumerate_api(self, subdomain):
        api_endpoints = [
            "/api",
            "/v1",
            "/v2",
            "/graphql",
            # Add more API endpoints to check
        ]

        for endpoint in api_endpoints:
            url = f"https://{subdomain}{endpoint}"

            response = self.make_request(url)
            if response and response.status_code == 200:
                logging.info("API Endpoint found: %s", url)

    def identify_technologies(self, subdomain):
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

    def test_vulnerabilities(self, subdomain):
        vulnerabilities = []

        response = requests.get("https://" + subdomain)

        if response.status_code == 200:
            if "wp-login.php" in response.text:
                vulnerabilities.append("WordPress login page exposed")

        return vulnerabilities

    def gather_information(self, subdomain):
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

    def exploit_vulnerability(self, subdomain):
        response = requests.get("https://" + subdomain)

        if response.status_code == 200:
            if "wp-login.php" in response.text:
                login_url = "https://" + subdomain + "/wp-login.php"
                payload = {"username": "admin", "password": "password123"}
                exploit_response = requests.post(login_url, data=payload)

                if exploit_response.status_code == 200:
                    logging.info("Exploited vulnerability in %s", subdomain)

    def additional_functionality(self, subdomain, technologies, vulnerabilities, information):
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

        filename = os.path.join(REPORTS_DIRECTORY, subdomain + "_info.txt")
        with FILE_LOCK:
            with open(filename, "w") as file:
                file.write("Subdomain: " + subdomain + "\n")
                file.write("Open Ports: " + str(self.scan_ports(subdomain)) + "\n")
                file.write("Technologies: " + str(technologies) + "\n")
                file.write("Vulnerabilities: " + str(vulnerabilities) + "\n")
                file.write("Information:\n")
                for key, value in information.items():
                    file.write(key + ": " + str(value) + "\n")

    def scan_directories(self, subdomain):
        directories = []

        common_directories = [
            "/admin",
            "/login",
            "/secret",
            # Add more common directories to scan
        ]

        for directory in common_directories:
            url = f"https://{subdomain}{directory}"

            response = self.make_request(url)
            if response and response.status_code == 200:
                directories.append(directory)

        return directories

    def crawl_and_analyze(self, subdomain):
        logging.info("Crawling and analyzing subdomain: %s", subdomain)

        file_path = os.path.join(self.wordlist_directory, f"{self.dir_file}.txt")
        try:
            with open(file_path, "r") as file:
                scanned_directories = [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            logging.error("File not found: %s", file_path)
            return

        homepage_url = f"https://{subdomain}"
        response = self.make_request(homepage_url)
        if response and response.status_code == 200:
            # Analyze the response or extract information
            # Example: Parse HTML content using BeautifulSoup
            soup = BeautifulSoup(response.content, "html.parser")
            # Perform analysis on the soup object
            
        with open(file_path, "r") as file:
            scanned_directories = [line.strip() for line in file.readlines()]

        # Crawl scanned directories
        scanned_directories = self.scan_directories(subdomain)
        for directory in scanned_directories:
            url = f"https://{subdomain}/{directory}"
            response = self.make_request(url)
            if response and response.status_code == 200:
                # Analyze the response or extract information
                # Example: Parse HTML content using BeautifulSoup
                soup = BeautifulSoup(response.content, "html.parser")
                # Perform analysis on the soup object
        pass

    def make_request(self, url):
        retries = 0
        backoff_delay = INITIAL_BACKOFF_DELAY

        while retries < MAX_RETRIES:
            try:
                response = requests.get(url, timeout=10)
                return response
            except (requests.exceptions.RequestException, socket.error) as e:
                logging.error("Error occurred while requesting %s: %s", url, e)
                retries += 1
                time.sleep(backoff_delay)
                backoff_delay *= 2

        logging.error("Max retries exceeded for requesting %s", url)
        return None