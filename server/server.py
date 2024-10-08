from flask import (
    Flask,
    render_template,
    request,
    url_for,
    redirect,
    flash,
    send_file,
    session,
    g,
)
import io
import os
from flask_migrate import Migrate
from model import db, User, AesFile, DesFile, Rc4File
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from config import Config
import logging
import time
import psycopg2
from contextlib import contextmanager
from sqlalchemy import create_engine

# Setup logging
logging.basicConfig(filename='encryption_performance.log', level=logging.INFO, format='%(asctime)s - %(message)s')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
error_logger = logging.getLogger('error_logger')
error_handler = logging.FileHandler('error.log')
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
error_logger.addHandler(error_handler)

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

app.config["UPLOAD_FOLDER"] = "uploads/"

# Database connection
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
connection = engine.raw_connection()

@contextmanager
def large_object_cursor():
    with connection.cursor() as cursor:
        yield cursor
    connection.commit()

# Function to ensure log header exists
def ensure_log_header():
    if not os.path.exists('performance.log'):
        with open('performance.log', 'w') as perf_log:
            perf_log.write("Operation,Method,File_OID,File_Size_Bytes,Time_Taken_Seconds\n")
    else:
        with open('performance.log', 'r+') as perf_log:
            first_line = perf_log.readline()
            if "Operation,Method,File_OID,File_Size_Bytes,Time_Taken_Seconds" not in first_line:
                perf_log.seek(0, 0)
                content = perf_log.read()
                perf_log.seek(0, 0)
                perf_log.write("Operation,Method,File_OID,File_Size_Bytes,Time_Taken_Seconds\n" + content)

# Encrypt AES large file in chunks
def encrypt_aes_file_in_chunks(file_oid, key, file_size):
    try:
        ensure_log_header()  # Ensure the log file has a header
        start_time = time.time()  # Start time tracking
        cipher = AES.new(key, AES.MODE_EAX)
        with large_object_cursor() as cursor:
            lo = connection.lobject(file_oid, mode='rb')  # Open existing large object
            encrypted_lo = connection.lobject(0, 'wb')    # Create new large object
            
            encrypted_lo.write(cipher.nonce)  # Write nonce (AES initialization vector)
            chunk = lo.read(1024 * 1024)  # Read in 1MB chunks
            
            while chunk:
                encrypted_lo.write(cipher.encrypt(chunk))
                chunk = lo.read(1024 * 1024)
                
            lo.close()
            encrypted_lo.close()
            
        end_time = time.time()  # End time tracking
        time_taken = end_time - start_time
        logging.info(f"AES encryption took {time_taken:.4f} seconds")
        with open('performance.log', 'a') as perf_log:
            perf_log.write(f"Encrypt,AES,{file_oid},{file_size},{time_taken:.4f}\n")
        return encrypted_lo.oid  # Return the OID of the new encrypted large object
    except Exception as e:
        error_logger.error(f"Error encrypting file with AES. Error: {str(e)}")
        raise

# Encrypt DES large file in chunks
def encrypt_des_file_in_chunks(file_oid, key, file_size):
    ensure_log_header()  # Ensure the log file has a header
    start_time = time.time()  # Start time tracking
    cipher = DES.new(key[:8].ljust(8, b'\0'), DES.MODE_CFB)
    with large_object_cursor() as cursor:
        lo = connection.lobject(file_oid, mode='rb')  # Open existing large object
        encrypted_lo = connection.lobject(0, 'wb')    # Create new large object
        
        encrypted_lo.write(cipher.iv)
        chunk = lo.read(1024 * 1024)  # Read in 1MB chunks
        while chunk:
            encrypted_lo.write(cipher.encrypt(chunk))
            chunk = lo.read(1024 * 1024)
        
        lo.close()
        encrypted_lo.close()
    
    end_time = time.time()  # End time tracking
    time_taken = end_time - start_time
    logging.info(f"DES encryption took {time_taken:.4f} seconds")
    with open('performance.log', 'a') as perf_log:
        perf_log.write(f"Encrypt,DES,{file_oid},{file_size},{time_taken:.4f}\n")
    return encrypted_lo.oid  # Return the OID of the new encrypted large object

# Encrypt RC4 large file in chunks
def encrypt_rc4_file_in_chunks(file_oid, key, file_size):
    ensure_log_header()  # Ensure the log file has a header
    start_time = time.time()  # Start time tracking
    cipher = ARC4.new(key)
    with large_object_cursor() as cursor:
        lo = connection.lobject(file_oid, mode='rb')  # Open existing large object
        encrypted_lo = connection.lobject(0, 'wb')    # Create new large object
        
        chunk = lo.read(1024 * 1024)  # Read in 1MB chunks
        while chunk:
            encrypted_lo.write(cipher.encrypt(chunk))
            chunk = lo.read(1024 * 1024)
        
        lo.close()
        encrypted_lo.close()
    
    end_time = time.time()  # End time tracking
    time_taken = end_time - start_time
    logging.info(f"RC4 encryption took {time_taken:.4f} seconds")
    with open('performance.log', 'a') as perf_log:
        perf_log.write(f"Encrypt,RC4,{file_oid},{file_size},{time_taken:.4f}\n")
    return encrypted_lo.oid  # Return the OID of the new encrypted large object

# Decrypt AES large file in chunks
def decrypt_aes_file_in_chunks(file_oid, key, file_size):
    try:
        ensure_log_header()  # Ensure the log file has a header
        start_time = time.time()  # Start time tracking
        with large_object_cursor() as cursor:
            lo = connection.lobject(file_oid, mode='rb')  # Open existing encrypted large object
            decrypted_lo = connection.lobject(0, 'wb')    # Create new large object for decrypted data
            
            nonce = lo.read(16)  # Read nonce
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            
            chunk = lo.read(1024 * 1024)  # Read in 1MB chunks
            while chunk:
                decrypted_lo.write(cipher.decrypt(chunk))
                chunk = lo.read(1024 * 1024)
                
            lo.close()
            decrypted_lo.close()
        
        end_time = time.time()  # End time tracking
        time_taken = end_time - start_time
        logging.info(f"AES decryption took {time_taken:.4f} seconds")
        with open('performance.log', 'a') as perf_log:
            perf_log.write(f"Decrypt,AES,{file_oid},{file_size},{time_taken:.4f}\n")
        return decrypted_lo.oid  # Return the OID of the new decrypted large object
    except Exception as e:
        error_logger.error(f"Error decrypting file with AES. Error: {str(e)}")
        raise

# Decrypt DES large file in chunks
def decrypt_des_file_in_chunks(file_oid, key, file_size):
    ensure_log_header()  # Ensure the log file has a header
    start_time = time.time()  # Start time tracking
    with large_object_cursor() as cursor:
        lo = connection.lobject(file_oid, mode='rb')  # Open existing encrypted large object
        decrypted_lo = connection.lobject(0, 'wb')    # Create new large object for decrypted data
        
        iv = lo.read(8)  # Read IV for DES
        cipher = DES.new(key[:8].ljust(8, b'\0'), DES.MODE_CFB, iv=iv)
        
        chunk = lo.read(1024 * 1024)  # Read in 1MB chunks
        while chunk:
            decrypted_lo.write(cipher.decrypt(chunk))
            chunk = lo.read(1024 * 1024)
        
        lo.close()
        decrypted_lo.close()
    
    end_time = time.time()  # End time tracking
    time_taken = end_time - start_time
    logging.info(f"DES decryption took {time_taken:.4f} seconds")
    with open('performance.log', 'a') as perf_log:
        perf_log.write(f"Decrypt,DES,{file_oid},{file_size},{time_taken:.4f}\n")
    return decrypted_lo.oid  # Return the OID of the new decrypted large object

# Decrypt RC4 large file in chunks
def decrypt_rc4_file_in_chunks(file_oid, key, file_size):
    ensure_log_header()  # Ensure the log file has a header
    start_time = time.time()  # Start time tracking
    cipher = ARC4.new(key)
    with large_object_cursor() as cursor:
        lo = connection.lobject(file_oid, mode='rb')  # Open existing encrypted large object
        decrypted_lo = connection.lobject(0, 'wb')    # Create new large object for decrypted data
        
        chunk = lo.read(1024 * 1024)  # Read in 1MB chunks
        while chunk:
            decrypted_lo.write(cipher.decrypt(chunk))
            chunk = lo.read(1024 * 1024)
        
        lo.close()
        decrypted_lo.close()
    
    end_time = time.time()  # End time tracking
    time_taken = end_time - start_time
    logging.info(f"RC4 decryption took {time_taken:.4f} seconds")
    with open('performance.log', 'a') as perf_log:
        perf_log.write(f"Decrypt,RC4,{file_oid},{file_size},{time_taken:.4f}\n")
    return decrypted_lo.oid  # Return the OID of the new decrypted large object

@app.route("/")
def home():
    return render_template("welcome.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("home"))
    user = User.query.get(session["user_id"])
    return render_template("dashboard.html")

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        encryption_method = request.form.get("encryption")
        file = request.files.get("file")
        user_id = session.get("user_id")

        # Validasi input metode enkripsi dan file
        if not encryption_method or encryption_method == "Choose an encryption method":
            flash("Please select an encryption method", "danger")
            return redirect(url_for("encrypt"))

        if not file:
            flash("No file selected", "danger")
            return redirect(url_for("encrypt"))

        try:
            user = User.query.get(user_id)
            
            # Hitung ukuran file dengan aman tanpa mengubah posisi pointer
            file.seek(0, os.SEEK_END)  # Pindahkan pointer ke akhir file
            file_size = file.tell()     # Dapatkan ukuran file dari posisi pointer
            file.seek(0)  # Kembalikan pointer ke awal file setelah menghitung ukuran

            # Simpan file ke Large Object di database
            with large_object_cursor() as cursor:
                lo_oid = connection.lobject(0, 'wb').oid  # Buat large object baru untuk file yang di-upload
                lo = connection.lobject(lo_oid, mode='wb')
                lo.write(file.read())  # Tulis ulang file ke large object
                lo.close()

            # Pilih metode enkripsi yang sesuai dan simpan hasilnya ke database
            if encryption_method == "AES":
                encrypted_oid = encrypt_aes_file_in_chunks(lo_oid, user.encryption_key, file_size)
                encrypted_file = AesFile(user_id=user_id, filename=file.filename, filetype=file.content_type, data_oid=encrypted_oid, file_size=file_size)
            elif encryption_method == "DES":
                encrypted_oid = encrypt_des_file_in_chunks(lo_oid, user.encryption_key, file_size)
                encrypted_file = DesFile(user_id=user_id, filename=file.filename, filetype=file.content_type, data_oid=encrypted_oid, file_size=file_size)
            elif encryption_method == "RC4":
                encrypted_oid = encrypt_rc4_file_in_chunks(lo_oid, user.encryption_key, file_size)
                encrypted_file = Rc4File(user_id=user_id, filename=file.filename, filetype=file.content_type, data_oid=encrypted_oid, file_size=file_size)

            # Simpan file terenkripsi ke database
            db.session.add(encrypted_file)
            db.session.commit()

            flash("File encrypted successfully", "success")
            return redirect(url_for("encrypt"))

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("encrypt"))

    return render_template("encrypt.html", current_page="Encrypt")


@app.route("/decrypt", methods=["POST", "GET"])
def decrypt():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session.get("user_id")

    aes_files = AesFile.query.filter_by(user_id=user_id).all()
    des_files = DesFile.query.filter_by(user_id=user_id).all()
    rc4_files = Rc4File.query.filter_by(user_id=user_id).all()

    if request.method == "POST":
        file_id = request.form.get("file_id")
        encryption_method = request.form.get("encryption")
        user = User.query.get(user_id)

        if encryption_method == "AES":
            encrypted_file = AesFile.query.filter_by(id=file_id, user_id=user_id).first()
        elif encryption_method == "DES":
            encrypted_file = DesFile.query.filter_by(id=file_id, user_id=user_id).first()
        elif encryption_method == "RC4":
            encrypted_file = Rc4File.query.filter_by(id=file_id, user_id=user_id).first()

        if not encrypted_file:
            flash("File not found.", "danger")
            return redirect(url_for("decrypt"))

        if encryption_method == "AES":
            decrypted_oid = decrypt_aes_file_in_chunks(encrypted_file.data_oid, user.encryption_key, encrypted_file.file_size)
        elif encryption_method == "DES":
            decrypted_oid = decrypt_des_file_in_chunks(encrypted_file.data_oid, user.encryption_key, encrypted_file.file_size)
        elif encryption_method == "RC4":
            decrypted_oid = decrypt_rc4_file_in_chunks(encrypted_file.data_oid, user.encryption_key, encrypted_file.file_size)

        with large_object_cursor() as cursor:
            lo = connection.lobject(decrypted_oid, mode='rb')
            decrypted_data = lo.read()
            lo.close()

        return send_file(io.BytesIO(decrypted_data), download_name=encrypted_file.filename, as_attachment=True, mimetype=encrypted_file.filetype)

    return render_template("decrypt.html", aes_files=aes_files, rc4_files=rc4_files, des_files=des_files)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email address already exists", "warning")
            return redirect(url_for("register"))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        new_user.encryption_key = get_random_bytes(16)

        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session.permanent = True
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
