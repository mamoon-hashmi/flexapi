# post_data.py
import requests

url = "http://localhost:5000/api/mock/mamoon-c5de6b/users"

data = {
    "name": "mamoon",

}

response = requests.post(url, json=data)

print("POST Status:", response.status_code)
print("Response:", response.json())