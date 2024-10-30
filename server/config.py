import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or os.urandom(32)
    DB_USER = os.getenv('DB_USER', 'alvn')
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'alvn12345')
    DB_NAME = os.getenv('DB_NAME', 'ki')
    
    SQLALCHEMY_DATABASE_URI = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    PERMANENT_SESSION_LIFETIME = 1800  