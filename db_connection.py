import mysql.connector
import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv("important.env")

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )
print(os.getenv("DB_HOST"))