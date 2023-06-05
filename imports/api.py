import requests
import hashlib
import hmac
import string
import random

class APIPenetrationTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.token = None

    def generate_random_string(self, length):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def generate_signature(self, data, secret_key):
        signature = hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()
        return signature

    def login(self, username, password):
        login_url = self.base_url + '/login'
        data = {'username': username, 'password': password}
        response = self.session.post(login_url, json=data)

        if response.status_code == 200:
            self.token = response.json().get('token')
            return True

        return False

    def send_authenticated_request(self, method, path, headers=None, params=None, data=None):
        if not self.token:
            raise ValueError("No authentication token provided.")

        url = self.base_url + path
        headers = headers or {}
        headers['Authorization'] = f'Bearer {self.token}'

        response = self.session.request(method, url, headers=headers, params=params, json=data)
        return response

    def fuzz_payloads(self, method, path, headers=None, params=None, data=None):
        url = self.base_url + path
        headers = headers or {}

        payloads = [
            '{"username": "admin", "password": "password"}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            # Add more payloads as needed
        ]

        for payload in payloads:
            headers['Content-Type'] = 'application/json'
            response = self.session.request(method, url, headers=headers, params=params, data=payload)
            print(f'Request: {method} {url}')
            print(f'Payload: {payload}')
            print(f'Status Code: {response.status_code}')
            print(f'Response Body: {response.text}\n')

    def run_tests(self):
        if self.login('admin', 'password'):
            # Example authenticated request
            response = self.send_authenticated_request('GET', '/users')
            print(f'Request: GET /users')
            print(f'Status Code: {response.status_code}')
            print(f'Response Body: {response.text}\n')

            # Example payload fuzzing
            self.fuzz_payloads('POST', '/api/v1/users')

if __name__ == '__main__':
    base_url = 'https://api.example.com'  # Replace with the target API base URL
    tester = APIPenetrationTester(base_url)
    tester.run_tests()
