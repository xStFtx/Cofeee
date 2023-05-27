import socket

class Enumeration:
    @staticmethod
    def perform_service_enumeration(target, port):
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

def perform_enumeration(target):
    print("\nEnumeration:")
    print("1. Perform service enumeration")

    sub_choice = input("Enter your choice: ")

    if sub_choice == '1':
        Enumeration.perform_service_enumeration(target)
    else:
        print("Invalid choice. Please try again.")