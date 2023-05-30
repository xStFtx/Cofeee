from imports.scanner import Scanner

TARGET_DOMAINS = ["rapyd.org", "rapyd.net", "rapyd.com"]

if __name__ == "__main__":
    scanner = Scanner(TARGET_DOMAINS)
    scanner.run()
