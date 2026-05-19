import requests
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("BEEKNOEE_API_KEY")

response = requests.post(
    "https://platform.beeknoee.com/api/v1/chat/completions",
    headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer "+ API_KEY
    },
    json={
        "model": "claude-sonnet-4-6",
        "messages": [
            {"role": "user", "content": "Xin chào, Tôi là Alice. Tôi muốn biết số lượng Claude token trong câu này."}
        ]
    }
)

if response.status_code == 200:
    data = response.json()
    print("Response from API:", data)
else:    print(f"Request failed with status code {response.status_code}: {response.text}")