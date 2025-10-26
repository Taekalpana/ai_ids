import os
import requests
from dotenv import load_dotenv

load_dotenv()  # Load .env file if present

API_KEY = os.getenv("ABUSEIPDB_KEY")

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    response = requests.get(url, headers=headers, params=params)
    return response.json()

if __name__ == "__main__":
    test_ip = "8.8.8.8"  # Google DNS
    print(check_abuseipdb(test_ip))
