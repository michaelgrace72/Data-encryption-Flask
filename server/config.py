import os
from dotenv import load_dotenv


load_dotenv()

class Config:
  SECRET_KEY = os.urandom(32)
  user = os.getenv('DB_USER')
  host = os.getenv('DB_HOST')
  password = os.getenv('DB_PASS')
  database = os.getenv('DB_NAME')
  
  #construct the database URI
  SQLALCHEMY_DATABASE_URI = f'postgresql://{user}:{password}@{host}/{database}'
  SQLALCHEMY_Track_MODIFICATIONS = False