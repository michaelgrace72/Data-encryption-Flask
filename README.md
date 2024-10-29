# Encryption Application Using Flask

Developed by:
- **Mikha Gracia Sugiono**
- **Azarel Grahandito A**
- **Alvin Vincent Oswald Reba**

---

## Project Overview

This project is a Flask-based application for secure file management and sharing among users. The application leverages **Flask-Migrate** for managing database migrations and **SQLAlchemy** as the Object-Relational Mapper (ORM) to interact with PostgreSQL.

---

## System Requirements

Ensure you have the following prerequisites:
- **Python** 3.7 or higher
- **Pip** for managing Python packages
- **PostgreSQL** as the database
- **Virtual Environment** (optional but recommended)

---

## Installation

Follow these steps to set up the application:

### 1. Clone the Repository
```bash
git clone https://github.com/username/project-name.git
cd project-name
```

### 2. Create a Virtual Environment (Optional)
Creating a virtual environment is recommended to keep dependencies isolated.

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

### 3. Install Dependencies
Install the necessary packages using `requirements.txt`:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing, manually install key dependencies:

```bash
pip install Flask Flask-Migrate Flask-SQLAlchemy psycopg2-binary cryptography python-dotenv
```

### 4. Set Up PostgreSQL Database

1. **Access PostgreSQL**:
   ```bash
   psql -U postgres
   ```

2. **Create a Database and User for the Application**:
   ```sql
   CREATE DATABASE database_name;
   CREATE USER user_name WITH PASSWORD 'user_password';
   ALTER ROLE user_name SET client_encoding TO 'utf8';
   ALTER ROLE user_name SET default_transaction_isolation TO 'read committed';
   ALTER ROLE user_name SET timezone TO 'UTC';
   GRANT ALL PRIVILEGES ON DATABASE database_name TO user_name;
   ```

### 5. Configurations in `config.py`

The `config.py` file configures essential settings like the secret key, database credentials, and file storage location.

```python
import os

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
```

#### Configuration Details

1. **`SECRET_KEY`**: Ensures user session security and prevents CSRF attacks.
2. **Database Configuration (`DB_USER`, `DB_HOST`, `DB_PASSWORD`, `DB_NAME`)**: Specifies the PostgreSQL connection settings.
3. **`SQLALCHEMY_TRACK_MODIFICATIONS`**: Disables SQLAlchemy’s event system to conserve resources.
4. **`UPLOAD_FOLDER`**: Sets the directory for user-uploaded files, defaulting to an `uploads` folder.
5. **`PERMANENT_SESSION_LIFETIME`**: Sets session inactivity logout time to 1800 seconds (30 minutes).

#### Using `Config` in the Flask Application

To apply the configuration, load `Config` as follows:

```python
from config import Config
from flask import Flask

app = Flask(__name__)
app.config.from_object(Config)
```

---

### 6. Generate `MASTER_KEY`

To auto-generate a `MASTER_KEY`, use the `master.py` script, which saves the key to `.bashrc`. Run this step before proceeding with database migration.

```bash
python master.py
```

After executing the script, refresh the terminal to apply the new `MASTER_KEY` in the environment:

```bash
source ~/.bashrc
```

---

### 7. Initialize Database and Run Migrations

To set up the database structure, use Flask-Migrate.

1. **Initialize Flask-Migrate**:
   ```bash
   flask --app server db init
   ```

2. **Create Initial Migration**:
   ```bash
   flask --app server db migrate -m "Add public key and SymmetricKeyRequest models"
   ```

3. **Apply Migrations to Database**:
   ```bash
   flask --app server db upgrade
   ```

---

### 8. Run the Application

After setup, start the application with:

```bash
python server.py
```

The application will run by default at `http://127.0.0.1:5001/`.

---

## License

[Specify License Here]
