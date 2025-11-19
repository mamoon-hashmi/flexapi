# get_data.py
import requests

url = "http://localhost:5000/api/mock/mamoon-c5de6b/users"

response = requests.get(url)

print("GET Status:", response.status_code)
print("All Data:")
for user in response.json():
    print(f"→ {user}")