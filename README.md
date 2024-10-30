# **Encryption Application Using Flask**

Developed by:
- **Mikha Gracia Sugiono**
- **Azarel Grahandito A**
- **Alvin Vincent Oswald Reba**

---

## Project Overview

This Flask-based application provides secure file management and controlled file sharing for users. It includes features like encryption of files using **AES**, **DES**, or **RC4** algorithms via **PyCryptodome** for secure data protection. Users can securely upload, encrypt, share, and manage permissions on files within a collaborative environment. The application integrates **Flask-Migrate** for database migrations and **SQLAlchemy** to interact with a PostgreSQL database for managing stored files, users, and activity logs.

Key Libraries:
- **Flask-Migrate**: For database schema migrations.
- **SQLAlchemy**: ORM for handling PostgreSQL interactions.
- **PyCryptodome**: For AES, DES, and RC4 encryption and decryption algorithms.
- **Flask-Session**: For secure session management.

---

## System Requirements

- **Python** 3.7 or higher
- **Pip** (Python package manager)
- **PostgreSQL** as the primary database
- **Virtual Environment** (recommended for isolated dependencies)

---

## Installation Guide

Follow these steps to set up and run the application:

### 1. Clone the Repository
```bash
git clone https://github.com/username/project-name.git
cd project-name
```

### 2. Create a Virtual Environment (Optional but Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

### 3. Install Dependencies
Install required libraries using `requirements.txt`:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is unavailable, you can manually install key dependencies:

```bash
pip install Flask Flask-Migrate Flask-SQLAlchemy psycopg2-binary pycryptodome python-dotenv
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

### 5. Configuration in `config.py`

The `config.py` file contains settings for application configuration, including encryption parameters, database credentials, and the location of the uploaded files.

```python
import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or os.urandom(32)
    DB_USER = os.getenv('DB_USER', 'your_db_user')
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'your_db_password')
    DB_NAME = os.getenv('DB_NAME', 'your_db_name')
    SQLALCHEMY_DATABASE_URI = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    PERMANENT_SESSION_LIFETIME = 1800
```

### 6. Generating the `MASTER_KEY`

The application requires a **`MASTER_KEY`** for secure encryption and decryption. This key is auto-generated and stored securely in `.bashrc` to protect user-specific keys against unauthorized access.

1. Run the `master.py` script to create and store the `MASTER_KEY`:
   ```bash
   python master.py
   ```

2. Reload the terminal session to load the key into the environment:
   ```bash
   source ~/.bashrc
   ```

**Purpose of MASTER_KEY Storage in `.bashrc`**:
- By storing the `MASTER_KEY` in `.bashrc`, the application can retrieve the key only when necessary, preventing exposure of the key within the codebase or database.
- Each user's key is encrypted with this `MASTER_KEY`, adding a layer of security. Even if database access is compromised, encrypted user keys cannot be decrypted without the `MASTER_KEY` stored securely in the user’s environment.

### 7. Initialize and Migrate Database

Use Flask-Migrate to initialize and apply migrations:

1. **Initialize Migration Directory**:
   ```bash
   flask --app server db init
   ```

2. **Create a Migration**:
   ```bash
   flask --app server db migrate -m "Initial migration with tables and relationships"
   ```

3. **Apply Migrations**:
   ```bash
   flask --app server db upgrade
   ```

**If Migration Errors Occur**:
```bash
flask db stamp head
```

---

### 8. Run the Application

Start the Flask application:

```bash
python server.py
```

By default, the application runs at `http://127.0.0.1:5001/`.

---

## Key Features

1. **User Registration & Authentication**:
   - Secure login and session management using encrypted passwords.

2. **File Encryption & Storage**:
   - Users can encrypt files using AES, DES, or RC4 before uploading them. The files are encrypted client-side to ensure they remain protected in storage.

3. **Secure File Sharing**:
   - Users can request access to files shared by other users. File owners can review, approve, or reject requests with specific access durations.

4. **Activity Logging**:
   - Tracks key actions, such as file uploads, access requests, approvals, and downloads. Logs use usernames rather than IDs for easy identification.

5. **Access Management**:
   - Owners have control over shared files, including options to block, unblock, and revoke access to previously shared files.

6. **Session Management**:
   - Session timeout automatically logs out inactive users after 30 minutes, enhancing security.

---

## Project Structure

- **`server.py`**: Main application file defining routes and logic.
- **`config.py`**: Stores configuration settings (database credentials, session configurations).
- **`models.py`**: Contains database models (User, Files, ShareRequest, ActivityLog).
- **`templates/`**: HTML templates for user interaction.
- **`master.py`**: Generates the `MASTER_KEY` to encrypt/decrypt user data.
  
---

## Usage Guide

1. **Encrypting and Uploading Files**:
   - Users select an encryption algorithm and upload a file. The encrypted file is stored securely in the database.

2. **Requesting Access to Shared Files**:
   - Users can enter the username of another user to request access to their shared files. The owner of the file can approve or reject the request and set an access duration.

3. **Managing Access**:
   - File owners can view and manage incoming access requests, with options to approve, block, unblock, or delete access. Approved access can be time-limited based on the specified duration.

4. **Activity Logs**:
   - The system logs actions like encryption, file sharing, and access approvals, providing a comprehensive overview of recent activities using usernames for easy tracking.

---

## Security Considerations

1. **`MASTER_KEY` in `.bashrc`**:
   - The `MASTER_KEY`, used for encrypting user-specific keys, is stored in `.bashrc` for enhanced security, making it accessible only in a secure environment. This prevents key exposure in code or database, adding a layer of security to user data.

2. **User-Specific Encryption Keys**:
   - Each user’s encryption key is securely encrypted with the `MASTER_KEY`, ensuring that even if unauthorized access occurs, these keys remain protected.

3. **Session Timeout**:
   - User sessions expire after 30 minutes of inactivity, reducing the risk of unauthorized access through unattended sessions.

4. **Encrypted File Storage**:
   - Files are stored in their encrypted form, making it difficult for unauthorized users to retrieve meaningful data from the database directly.

---

## Potential Improvements

- **File Decryption Preview**: Allow users to preview files without downloading.
- **Admin Dashboard**: Add a management interface for admins to oversee user activity and manage permissions.
- **Role-Based Access Control (RBAC)**: Implement different user roles to improve access control.

---

## License

[Specify License Here]

---
