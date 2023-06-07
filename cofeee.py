from imports.scanner import Scanner
from imports.fuzzer import Fuzzer
from imports.api import APIPenetrationTester

TARGET_DOMAINS = ["napoleoncasino.be" , "napoleondice.be", "napoleongames.be", "napoleonsports.be"]
TARGET_LINK_FUZZING = f'https://{TARGET_DOMAINS[0]}'
WORDLIST = r"\fuzzing.txt"

if __name__ == "__main__":
    scanner = Scanner(TARGET_DOMAINS)
    scanner.run()

    fuzzer = Fuzzer(TARGET_LINK_FUZZING,WORDLIST)
    fuzzer.run()