# config.py
from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    MONGO_URI = os.getenv('MONGO_URI')
    SMTP_EMAIL = os.getenv('SMTP_EMAIL')
    SMTP_APP_PASSWORD = os.getenv('SMTP_APP_PASSWORD')