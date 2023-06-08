import subprocess
import concurrent.futures

class Fuzzer:
    def __init__(self, target_url, wordlist_path):
        self.target_url = target_url
        self.wordlist_path = wordlist_path

    def fuzz_directories(self):
        cmd = [
            'ffuf',
            '-u', f'{self.target_url}/FUZZ',
            '-w', f'wordlists/{self.wordlist_path}',
            '-t', '50',
            '-mc', '200',
            '-fs', '0'
        ]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            print(stdout)
        else:
            print(f'Error occurred while fuzzing directories: {stderr}')

    def fuzz_files(self, extension):
        cmd = [
            'ffuf',
            '-u', f'{self.target_url}/FUZZ{extension}',
            '-w', f'wordlists/{self.wordlist_path}',
            '-t', '50',
            '-mc', '200',
            '-fs', '0'
        ]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            print(stdout)
        else:
            print(f'Error occurred while fuzzing files with extension {extension}: {stderr}')

    async def run(self):
        print("Starting fuzzing...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=250) as executor:
            executor.submit(self.fuzz_directories)

            extensions = ['.php', '.html', '.txt']  # Add more file extensions as needed
            futures = [executor.submit(self.fuzz_files, extension) for extension in extensions]

            concurrent.futures.wait(futures)

        print("Fuzzing completed.")
