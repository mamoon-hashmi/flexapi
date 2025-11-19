# delete_data.py
import requests

user_id = "691db0a52b65df5a4389c760"

url = f"http://localhost:5000/api/mock/mamoon-c5de6b/users/{user_id}"

response = requests.delete(url)

print("DELETE Status:", response.status_code)
print("Response:", response.json())

if response.status_code == 200:
    print(f"User {user_id} successfully delete ho gaya!")