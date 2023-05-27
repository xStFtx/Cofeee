import subprocess
import socket
import requests
import whois
import dns.resolver

class Reconnaissance:
    @staticmethod
    def perform_whois_lookup(target):
        try:
            w = whois.whois(target)
            print(w)
        except whois.parser.PywhoisError as e:
            print(f"Error performing WHOIS lookup: {str(e)}")

    @staticmethod
    def perform_dns_enumeration(target):
        try:
            if not target.isdigit():
                target = socket.gethostbyname(target)
            dns_records = dns.resolver.query(target, 'A')
            for record in dns_records:
                print(record)
        except (dns.resolver.NXDOMAIN, socket.gaierror) as e:
            print(f"Error performing DNS enumeration: {str(e)}")

    @staticmethod
    def perform_subdomain_enumeration(target):
        try:
            if not target.isdigit():
                subprocess.run(['sublist3r', '-d', target])
            else:
                print("Please provide a domain name for subdomain enumeration.")
        except FileNotFoundError:
            print("sublist3r tool not found. Install sublist3r or provide another subdomain enumeration tool.")

    @staticmethod
    def extract_service_headers(target):
        try:
            response = requests.get(target)
            print(response.headers)
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving service headers: {str(e)}")

    @staticmethod
    def perform_fuzzing(target, wordlist):
        try:
            # Perform fuzzing using wfuzz
            subprocess.run(['wfuzz', '-c', '-z', 'file', '--input', wordlist, target])
        except FileNotFoundError:
            print("wfuzz tool not found. Install wfuzz or provide another fuzzing tool.")

def perform_reconnaissance(target):
    print("\nReconnaissance:")
    print("1. Perform WHOIS lookup")
    print("2. Perform DNS enumeration")
    print("3. Perform subdomain enumeration")
    print("4. Extract service headers")
    print("5. Perform fuzzing")

    sub_choice = input("Enter your choice: ")

    if sub_choice == '1':
        Reconnaissance.perform_whois_lookup(target)
    elif sub_choice == '2':
        Reconnaissance.perform_dns_enumeration(target)
    elif sub_choice == '3':
        Reconnaissance.perform_subdomain_enumeration(target)
    elif sub_choice == '4':
        target = 'https://' + target
        Reconnaissance.extract_service_headers(target)
    elif sub_choice == '5':
        target = 'https://' + target + '/'
        wordlist = input("Enter the path to the wordlist: ")
        Reconnaissance.perform_fuzzing(target, wordlist)
    else:
        print("Invalid choice. Please try again.")
