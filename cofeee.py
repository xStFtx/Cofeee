from imports.scanner import Scanner
from importsfuzzy import Fuzzer

TARGET_DOMAINS = ["rapyd.org", "rapyd.net", "rapyd.com"]
TARGET_LINKS = ['https://' + domain for domain in TARGET_DOMAINS]
WORDLIST = ""

if __name__ == "__main__":
    scanner = Scanner(TARGET_DOMAINS)
    scanner.run()

    fuzzer = Fuzzer(TARGET_DOMAINS)
    fuzzer.run()
