import socket
from imports.reconnaissance import perform_reconnaissance
from imports.scanning import perform_scanning
from imports.enumeration import perform_enumeration
from imports.reporting import Reporting
from imports.post_exploitation import perform_post_exploitation
from imports.vulnerability_assessment import perform_vulnerability_assessment
from imports.exploitation import perform_exploitation

def get_targets():
    targets = []
    target = input("Enter the domain or IP address: ")
    if target:
        try:
            ip = socket.gethostbyname(target)
            targets.append(ip)
        except socket.gaierror as e:
            print(f"Error resolving domain: {str(e)}")
    return targets


def main():
    targets = get_targets()
    
    option_functions = {
        '1': perform_reconnaissance,
        '2': perform_scanning,
        '3': perform_enumeration,
        '4': perform_vulnerability_assessment,
        '5': perform_exploitation,
        '6': perform_post_exploitation,
        '7': Reporting.generate_report
    }

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

        if choice == '0':
            break

        # Check if the selected option exists in the dictionary
        if choice in option_functions:
            # Call the corresponding function based on the selected option
            option_functions[choice](targets)
        else:
            print("Invalid choice. Please try again.")


if __name__ == '__main__':
    main()
