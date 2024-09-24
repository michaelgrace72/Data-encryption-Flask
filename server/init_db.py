import os 
import sys
import psycopg2

# Load environment variables
conn = psycopg2.connect(
    host=os.getenv('DB_HOST'),
    dbname=os.getenv('DB_NAME'),
    dbuser=os.getenv('DB_USER'),
    password=os.getenv('DB_PASS')
)

# Open a cursor to perform database operations
cur = conn.cursor()

# Commands

