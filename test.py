import asyncio
import aiohttp
import socket
from bs4 import BeautifulSoup
import nmap
import os
import threading
import whois
import logging
from urllib.parse import urljoin
import requests

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

wlf = "wordlists/dirbrute.txt"


class Scanner:
    def __init__(self, target_domains):
        self.target_domains = target_domains
        self.wordlist_directory = "wordlists"
        self.dir_file = "common_dir.txt"

    async def run(self):
        # Create Reports directory if it doesn't exist
        if not os.path.exists(REPORTS_DIRECTORY):
            os.makedirs(REPORTS_DIRECTORY)

        async with aiohttp.ClientSession() as session:
            tasks = []
            for target in self.target_domains:
                subdomains = await self.find_subdomains(target)

                for subdomain in subdomains:
                    url = "https://" + subdomain

                    task = asyncio.ensure_future(self.handle_request(session, url))
                    tasks.append((subdomain, task))

            for subdomain, task in tasks:
                response = await task
                if response and response.status == 200:
                    self.process_subdomain(subdomain, target)
                    thread = threading.Thread(target=self.crawl_and_analyze, args=(subdomain,))
                    thread.start()
                    self.perform_web_application_fingerprinting(subdomain)
                else:
                    logging.error("Failed to retrieve response for subdomain: %s", subdomain)

        self.port_scan()

    async def find_subdomains(self, target):
        subdomains = []

        async def resolve_subdomain(subdomain):
            domain = subdomain + "." + target
            try:
                await asyncio.get_event_loop().getaddrinfo(domain, None)
                subdomains.append(domain)
            except socket.error:
                pass

        await asyncio.gather(*[resolve_subdomain(subdomain) for subdomain in COMMON_SUBDOMAINS])

        return subdomains

    async def handle_request(self, session, url):
        retries = 0
        backoff_delay = INITIAL_BACKOFF_DELAY

        while retries < MAX_RETRIES:
            try:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        return response
                    else:
                        return None  # Ignore non-200 responses
            except (aiohttp.ClientError, socket.error) as e:
                logging.error("Error occurred while requesting %s: %s", url, e)
                retries += 1
                await asyncio.sleep(backoff_delay)
                backoff_delay *= 2

        logging.error("Max retries exceeded for requesting %s", url)
        return None


    def process_subdomain(self, subdomain, target):
        logging.info("Processing subdomain: %s", subdomain)

        try:
            # Create subdomain directory if it doesn't exist
            target_dir = os.path.join(REPORTS_DIRECTORY, target)
            subdomain_dir = os.path.join(target_dir, subdomain)
            if not os.path.exists(subdomain_dir):
                os.makedirs(subdomain_dir)

            self.save_screenshot(subdomain, subdomain_dir)
            self.save_html(subdomain, subdomain_dir)
            self.save_whois(subdomain, subdomain_dir)
        except Exception as e:
            logging.error("Error occurred while processing subdomain %s: %s", subdomain, e)

    def crawl_and_analyze(self, subdomain):
        logging.info("Crawling and analyzing subdomain: %s", subdomain)

        file_path = os.path.join(self.wordlist_directory, self.dir_file)
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

        # Crawl scanned directories
        for directory in scanned_directories:
            # Construct the URL using subdomain and directory separately
            url = urljoin(f"https://{subdomain}/", directory)
            response = self.make_request(url)
            if response:
                if response.status_code == 200:
                    # Analyze the response or extract information
                    # Example: Parse HTML content using BeautifulSoup
                    soup = BeautifulSoup(response.content, "html.parser")
                    # Perform analysis on the soup object
                elif response.status_code != 404:
                    logging.error("Failed to retrieve response for URL: %s. Status code: %s", url, response.status_code)

    def save_screenshot(self, subdomain, subdomain_dir):
        pass

    def save_html(self, subdomain, subdomain_dir):
        url = "https://" + subdomain
        filename = os.path.join(subdomain_dir, "index.html")

        try:
            response = self.make_request(url)
            if response and response.status_code == 200:
                with open(filename, "w") as f:
                    f.write(response.text)
            else:
                logging.error("Failed to save HTML for %s. Status code: %s", url, response.status_code)
        except (aiohttp.ClientError, socket.error, FileNotFoundError) as e:
            logging.error("Error occurred while saving HTML for %s: %s", url, e)

    def save_whois(self, subdomain, subdomain_dir):
        domain = subdomain.split("://")[-1]
        filename = os.path.join(subdomain_dir, "whois.txt")

        try:
            w = whois.whois(domain)
            with open(filename, "w") as f:
                f.write(str(w))
        except (whois.parser.PywhoisError, socket.error, AttributeError) as e:
            logging.error("Error occurred while saving WHOIS for %s: %s", subdomain, e)

    def perform_web_application_fingerprinting(self, subdomain):
        pass

    def make_request(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()  # Check for HTTP errors
            return response
        except Exception as e:
            logging.error("Error occurred while making request to %s: %s", url, e)
            return None

    def port_scan(self):
        nm = nmap.PortScanner()

        for target in self.target_domains:
            logging.info("Scanning ports for target: %s", target)
            for port in COMMON_PORTS:
                try:
                    result = nm.scan(target, str(port))
                    state = result["scan"][target]["tcp"][port]["state"]
                    logging.info("Port %d is %s for target %s", port, state, target)
                except Exception as e:
                    logging.error("Error occurred while scanning port %d for target %s: %s", port, target, e)


if __name__ == "__main__":
    target_domains = ["instagram.com"]  # Replace with your target domains

    scanner = Scanner(target_domains)
    asyncio.run(scanner.run())
