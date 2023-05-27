import subprocess
import socket
import requests
import whois
import dns.resolver
import threading

class Scanning:
    @staticmethod
    def perform_port_scanning(target):
        try:
            subprocess.run(['nmap', '-p-', target])
        except FileNotFoundError:
            print("nmap tool not found. Install nmap or provide another port scanning tool.")

    @staticmethod
    def run_port_scanning(target):
        try:
            result = subprocess.check_output(['nmap', '-p-', target])
            open_ports = []
            lines = result.decode().split('\n')
            for line in lines:
                if '/tcp' in line:
                    port = line.split('/')[0]
                    open_ports.append(port)
            return open_ports
        except FileNotFoundError:
            print("nmap tool not found. Install nmap or provide another port scanning tool.")


def perform_scanning(target):
    print("\nScanning:")
    print("1. Perform port scanning")

    sub_choice = input("Enter your choice: ")

    if sub_choice == '1':
        Scanning.perform_port_scanning(target)
    else:
        print("Invalid choice. Please try again.")