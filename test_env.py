# test_env.py
import os
from dotenv import load_dotenv

load_dotenv("important.env")  # Load from .env

print("DB_HOST =", os.getenv("DB_HOST"))
