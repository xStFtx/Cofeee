import asyncio
from imports.scanner import Scanner
from imports.fuzzer import Fuzzer
from imports.api import APIPenetrationTester

TARGET_DOMAINS = ["instagram.com"]
TARGET_LINK_FUZZING = f'https://{TARGET_DOMAINS[0]}'
WORDLIST = r"\fuzzing.txt"

async def main():
    scanner = Scanner(TARGET_DOMAINS)
    scanner_task = asyncio.create_task(scanner.run())

    fuzzer = Fuzzer(TARGET_LINK_FUZZING, WORDLIST)
    fuzzer_task = asyncio.create_task(fuzzer.run())

    await asyncio.gather(scanner_task, fuzzer_task)

if __name__ == "__main__":
    asyncio.run(main())
