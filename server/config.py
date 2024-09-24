import os
from dotenv import load_dotenv


load_dotenv()

class Config:
  SECRET_KEY = os.getenv('SECRET_KEY')
  user = os.getenv('DB_USER')
  host = os.getenv('DB_HOST')
  password = os.getenv('DB_PASS')
  database = os.getenv('DB_NAME')
  
  #construct the database URI
  SQLALCHEMY_DATABASE_URI = f'postgresql://{user}:{password}@{host}/{database}'
  SQLALCHEMY_Track_MODIFICATIONS = False

  # set session expiration time to 30 minutes
  PERMANENT_SESSION_LIFETIME = 1800