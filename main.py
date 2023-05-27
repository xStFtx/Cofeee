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
            subprocess.run(['sublist3r', '-d', target])
        except FileNotFoundError:
            print("sublist3r tool not found. Install sublist3r or provide another subdomain enumeration tool.")

    @staticmethod
    def extract_service_headers(target):
        try:
            response = requests.get(target)
            print(response.headers)
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving service headers: {str(e)}")

class Scanning:
    @staticmethod
    def perform_port_scanning(target):
        try:
            subprocess.run(['nmap', '-p-', target])
        except FileNotFoundError:
            print("nmap tool not found. Install nmap or provide another port scanning tool.")

class Enumeration:
    @staticmethod
    def perform_service_enumeration(target):
        open_ports = Scanning.perform_port_scanning(target)
        for port in open_ports:
            service_info = Enumeration.get_service_info(target, port)
            print(f"Port: {port}\tService: {service_info}")

    @staticmethod
    def get_service_info(target, port):
        service_info = "Unknown"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            response = sock.recv(1024)
            service_info = response.decode().splitlines()[0]
            sock.close()
        except Exception as e:
            print(f"Error retrieving service info for port {port}: {str(e)}")
        return service_info

class VulnerabilityAssessment:
    @staticmethod
    def perform_vulnerability_checks(target):
        scan_results = VulnerabilityAssessment.run_vulnerability_scan(target)
        VulnerabilityAssessment.process_scan_results(scan_results)

    @staticmethod
    def run_vulnerability_scan(target):
        try:
            command = ['openvas-cli', '-c', 'Full and Fast', '-T', target]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            scan_results = output.decode()
            return scan_results
        except FileNotFoundError:
            print("openvas-cli tool not found. Install OpenVAS or provide another vulnerability scanning tool.")

    @staticmethod
    def process_scan_results(scan_results):
        print("Vulnerability scan results:")
        print(scan_results)

    @staticmethod
    def perform_web_vulnerability_scanning(target):
        try:
            subprocess.run(['zap', '-target', target, '-quickurl', target])
        except FileNotFoundError:
            print("OWASP ZAP tool not found. Install OWASP ZAP or provide another web vulnerability scanning tool.")

    @staticmethod
    def perform_network_vulnerability_scanning(target):
        scan_results = Scanning.run_network_scan(target)
        VulnerabilityAssessment.process_scan_results(scan_results)

    @staticmethod
    def run_network_scan(target):
        try:
            command = ['nmap', '-A', target]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            scan_results = output.decode()
            return scan_results
        except FileNotFoundError:
            print("nmap tool not found. Install nmap or provide another network vulnerability scanning tool.")

class Exploitation:
    @staticmethod
    def develop_exploit_module(vulnerability):
        # Implement the code to develop an exploit module
        pass

    @staticmethod
    def automate_exploitation(target):
        # Implement the code to automate exploitation
        pass

    @staticmethod
    def gain_access(target):
        # Implement the code to gain access to the system
        pass

    @staticmethod
    def enumerate_system_information(target):
        # Implement the code to enumerate system information
        pass

class Reporting:
    @staticmethod
    def generate_report(findings):
        # Implement the code to generate a report
        pass

def get_target():
    target = input("Enter the domain or IP address: ")
    if not target.isdigit():
        try:
            target = socket.gethostbyname(target)
        except socket.gaierror as e:
            print(f"Error resolving domain: {str(e)}")
            return None
    return target

if __name__ == '__main__':
    while True:
        print("\nSelect an action:")
        print("1. Perform Reconnaissance")
        print("2. Perform Scanning")
        print("3. Perform Enumeration")
        print("4. Perform Vulnerability Assessment")
        print("5. Perform Exploitation")
        print("6. Perform Post-Exploitation")
        print("7. Generate Report")
        print("0. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            target = get_target()
            if target:
                print("\nReconnaissance:")
                print("1. Perform WHOIS lookup")
                print("2. Perform DNS enumeration")
                print("3. Perform subdomain enumeration")
                print("4. Extract service headers")

                sub_choice = input("Enter your choice: ")

                if sub_choice == '1':
                    Reconnaissance.perform_whois_lookup(target)
                elif sub_choice == '2':
                    Reconnaissance.perform_dns_enumeration(target)
                elif sub_choice == '3':
                    Reconnaissance.perform_subdomain_enumeration(target)
                elif sub_choice == '4':
                    Reconnaissance.extract_service_headers(target)
                else:
                    print("Invalid choice. Please try again.")

        elif choice == '2':
            target = get_target()
            if target:
                print("\nScanning:")
                print("1. Perform port scanning")

                sub_choice = input("Enter your choice: ")

                if sub_choice == '1':
                    Scanning.perform_port_scanning(target)
                else:
                    print("Invalid choice. Please try again.")

        elif choice == '3':
            target = get_target()
            if target:
                print("\nEnumeration:")
                print("1. Perform service enumeration")

                sub_choice = input("Enter your choice: ")

                if sub_choice == '1':
                    Enumeration.perform_service_enumeration(target)
                else:
                    print("Invalid choice. Please try again.")

        elif choice == '4':
            target = get_target()
            if target:
                print("\nVulnerability Assessment:")
                print("1. Perform vulnerability checks")
                print("2. Perform web vulnerability scanning")
                print("3. Perform network vulnerability scanning")

                sub_choice = input("Enter your choice: ")

                if sub_choice == '1':
                    VulnerabilityAssessment.perform_vulnerability_checks(target)
                elif sub_choice == '2':
                    VulnerabilityAssessment.perform_web_vulnerability_scanning(target)
                elif sub_choice == '3':
                    VulnerabilityAssessment.perform_network_vulnerability_scanning(target)
                else:
                    print("Invalid choice. Please try again.")

        elif choice == '5':
            target = get_target()
            if target:
                print("\nExploitation:")
                print("1. Develop exploit module")
                print("2. Automate exploitation")

                sub_choice = input("Enter your choice: ")

                if sub_choice == '1':
                    vulnerability = input("Enter the vulnerability: ")
                    Exploitation.develop_exploit_module(vulnerability)
                elif sub_choice == '2':
                    Exploitation.automate_exploitation(target)
                else:
                    print("Invalid choice. Please try again.")

        elif choice == '6':
            target = get_target()
            if target:
                print("\nPost-Exploitation:")
                print("1. Gain access")
                print("2. Enumerate system information")

                sub_choice = input("Enter your choice: ")

                if sub_choice == '1':
                    Exploitation.gain_access(target)
                elif sub_choice == '2':
                    Exploitation.enumerate_system_information(target)
                else:
                    print("Invalid choice. Please try again.")

        elif choice == '7':
            findings = input("Enter the findings: ")
            Reporting.generate_report(findings)

        elif choice == '0':
            break

        else:
            print("Invalid choice. Please try again.")
