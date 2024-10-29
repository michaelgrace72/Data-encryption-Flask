from flask import (
    Flask,
    render_template,
    request,
    url_for,
    redirect,
    flash,
    send_file,
    session,
)
import io
import os
import hashlib
from flask_migrate import Migrate
from model import db, User, AesFile, DesFile, Rc4File, ShareRequest, UserKeys
from Crypto.Cipher import AES, DES, ARC4,PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from config import Config
import logging
import time
import base64
from contextlib import contextmanager
from sqlalchemy import create_engine
from datetime import datetime, timedelta


# Load master key from environment variable
MASTER_KEY = os.getenv("MASTER_KEY")
if not MASTER_KEY:
    raise EnvironmentError("MASTER_KEY environment variable not found. Please set it in ~/.bashrc")

# Verify length of MASTER_KEY
REQUIRED_MASTER_KEY_LENGTH = 64  # 64 characters for a 256-bit key in hexadecimal format
if len(MASTER_KEY) != REQUIRED_MASTER_KEY_LENGTH:
    raise ValueError(f"MASTER_KEY must be {REQUIRED_MASTER_KEY_LENGTH} characters long (256-bit in hexadecimal).")

# Proceed with hashing or further use
MASTER_KEY_HASH = hashlib.sha256(bytes.fromhex(MASTER_KEY)).hexdigest()

# Flask setup
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

# Setup logging
logging.basicConfig(filename='encryption_performance.log', level=logging.INFO, format='%(asctime)s - %(message)s')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
error_logger = logging.getLogger('error_logger')
error_handler = logging.FileHandler('error.log')
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
error_logger.addHandler(error_handler)

# Database connection
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
connection = engine.raw_connection()

app.config["UPLOAD_FOLDER"] = "uploads/"

@contextmanager
def large_object_cursor():
    with connection.cursor() as cursor:
        yield cursor
    connection.commit()

# Encrypt and decrypt user key using master key
def encrypt_user_key(user_key, master_key):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    derived_key = PBKDF2(master_key, salt, dkLen=32)
    cipher = AES.new(derived_key, AES.MODE_CFB, iv)
    encrypted_key = cipher.encrypt(user_key)
    return base64.b64encode(salt + iv + encrypted_key)

def decrypt_user_key(encrypted_key_b64, master_key):
    encrypted_data = base64.b64decode(encrypted_key_b64)
    salt, iv, encrypted_key = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    derived_key = PBKDF2(master_key, salt, dkLen=32)
    cipher = AES.new(derived_key, AES.MODE_CFB, iv)
    return cipher.decrypt(encrypted_key)

@app.route("/")
def home():
    return render_template("welcome.html")

# Function to ensure log header exists
def ensure_log_header():
    if not os.path.exists('performance.log'):
        with open('performance.log', 'w') as perf_log:
            perf_log.write("Operation,Method,File_OID,File_Size_Bytes,Time_Taken_Seconds\n")

# Encrypt AES large file in chunks
def encrypt_aes_file_in_chunks(file_oid, key, file_size):
    try:
        ensure_log_header()
        start_time = time.time()
        cipher = AES.new(key, AES.MODE_EAX)
        with large_object_cursor() as cursor:
            lo = connection.lobject(file_oid, mode='rb')
            encrypted_lo = connection.lobject(0, 'wb')
            
            encrypted_lo.write(cipher.nonce)
            chunk = lo.read(1024 * 1024)
            
            while chunk:
                encrypted_lo.write(cipher.encrypt(chunk))
                chunk = lo.read(1024 * 1024)
                
            lo.close()
            encrypted_lo.close()
            
        end_time = time.time()
        time_taken = end_time - start_time
        logging.info(f"AES encryption took {time_taken:.4f} seconds")
        with open('performance.log', 'a') as perf_log:
            perf_log.write(f"Encrypt,AES,{file_oid},{file_size},{time_taken:.4f}\n")
        return encrypted_lo.oid
    except Exception as e:
        error_logger.error(f"Error encrypting file with AES. Error: {str(e)}")
        raise

# Encrypt DES large file in chunks
def encrypt_des_file_in_chunks(file_oid, key, file_size):
    ensure_log_header()
    start_time = time.time()
    cipher = DES.new(key[:8].ljust(8, b'\0'), DES.MODE_CFB)
    with large_object_cursor() as cursor:
        lo = connection.lobject(file_oid, mode='rb')
        encrypted_lo = connection.lobject(0, 'wb')
        
        encrypted_lo.write(cipher.iv)
        chunk = lo.read(1024 * 1024)
        while chunk:
            encrypted_lo.write(cipher.encrypt(chunk))
            chunk = lo.read(1024 * 1024)
        
        lo.close()
        encrypted_lo.close()
    
    end_time = time.time()
    time_taken = end_time - start_time
    logging.info(f"DES encryption took {time_taken:.4f} seconds")
    with open('performance.log', 'a') as perf_log:
        perf_log.write(f"Encrypt,DES,{file_oid},{file_size},{time_taken:.4f}\n")
    return encrypted_lo.oid

# Encrypt RC4 large file in chunks
def encrypt_rc4_file_in_chunks(file_oid, key, file_size):
    ensure_log_header()
    start_time = time.time()
    cipher = ARC4.new(key)
    with large_object_cursor() as cursor:
        lo = connection.lobject(file_oid, mode='rb')
        encrypted_lo = connection.lobject(0, 'wb')
        
        chunk = lo.read(1024 * 1024)
        while chunk:
            encrypted_lo.write(cipher.encrypt(chunk))
            chunk = lo.read(1024 * 1024)
        
        lo.close()
        encrypted_lo.close()
    
    end_time = time.time()
    time_taken = end_time - start_time
    logging.info(f"RC4 encryption took {time_taken:.4f} seconds")
    with open('performance.log', 'a') as perf_log:
        perf_log.write(f"Encrypt,RC4,{file_oid},{file_size},{time_taken:.4f}\n")
    return encrypted_lo.oid

def decrypt_aes_file_in_chunks(file_oid, key, file_size):
    try:
        ensure_log_header()
        start_time = time.time()
        
        decrypted_data = io.BytesIO()
        
        with large_object_cursor() as cursor:
            lo = connection.lobject(file_oid, mode='rb')
            
            # Read nonce first
            nonce = lo.read(16)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            
            # Read and decrypt in chunks
            while True:
                chunk = lo.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                decrypted_data.write(decrypted_chunk)
            
            lo.close()
        
        end_time = time.time()
        time_taken = end_time - start_time
        logging.info(f"AES decryption took {time_taken:.4f} seconds")
        
        with open('performance.log', 'a') as perf_log:
            perf_log.write(f"Decrypt,AES,{file_oid},{file_size},{time_taken:.4f}\n")
        
        return decrypted_data.getvalue()
        
    except Exception as e:
        error_logger.error(f"Error decrypting file with AES: {str(e)}")
        raise

def decrypt_des_file_in_chunks(file_oid, key, file_size):
    try:
        ensure_log_header()
        start_time = time.time()
        
        decrypted_data = io.BytesIO()
        
        with large_object_cursor() as cursor:
            lo = connection.lobject(file_oid, mode='rb')
            
            # Read IV first
            iv = lo.read(8)
            cipher = DES.new(key[:8], DES.MODE_CFB, iv=iv)
            
            # Read and decrypt in chunks
            while True:
                chunk = lo.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                decrypted_data.write(decrypted_chunk)
            
            lo.close()
        
        end_time = time.time()
        time_taken = end_time - start_time
        logging.info(f"DES decryption took {time_taken:.4f} seconds")
        
        with open('performance.log', 'a') as perf_log:
            perf_log.write(f"Decrypt,DES,{file_oid},{file_size},{time_taken:.4f}\n")
        
        return decrypted_data.getvalue()
        
    except Exception as e:
        error_logger.error(f"Error decrypting file with DES: {str(e)}")
        raise

def decrypt_rc4_file_in_chunks(file_oid, key, file_size):
    try:
        ensure_log_header()
        start_time = time.time()
        
        decrypted_data = io.BytesIO()
        cipher = ARC4.new(key)
        
        with large_object_cursor() as cursor:
            lo = connection.lobject(file_oid, mode='rb')
            
            # Read and decrypt in chunks
            while True:
                chunk = lo.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                decrypted_data.write(decrypted_chunk)
            
            lo.close()
        
        end_time = time.time()
        time_taken = end_time - start_time
        logging.info(f"RC4 decryption took {time_taken:.4f} seconds")
        
        with open('performance.log', 'a') as perf_log:
            perf_log.write(f"Decrypt,RC4,{file_oid},{file_size},{time_taken:.4f}\n")
        
        return decrypted_data.getvalue()
        
    except Exception as e:
        error_logger.error(f"Error decrypting file with RC4: {str(e)}")
        raise

# Add these functions after the existing user key encryption functions
def generate_user_keypair():
    """Generate RSA keypair for a user"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_private_key(private_key, user_key):
    """Encrypt user's private key with their symmetric key"""
    cipher = AES.new(user_key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted_data = cipher.encrypt(private_key)
    return base64.b64encode(nonce + encrypted_data).decode('utf-8')

def decrypt_private_key(encrypted_private_key, user_key):
    """Decrypt user's private key with their symmetric key"""
    encrypted_data = base64.b64decode(encrypted_private_key.encode('utf-8'))
    nonce = encrypted_data[:16]
    cipher = AES.new(user_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(encrypted_data[16:])

def encrypt_sharing_key(sharing_key, public_key):
    """Encrypt the sharing key with recipient's public key"""
    recipient_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(recipient_key)
    encrypted_key = cipher.encrypt(sharing_key)
    return base64.b64encode(encrypted_key).decode('utf-8')


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("home"))
    user = User.query.get(session["user_id"])
    return render_template("dashboard.html")

# Routes for register, login, encrypt, and decrypt functionalities
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

        # Generate user's encryption key and keypair
        user_key = get_random_bytes(16)
        encrypted_user_key = encrypt_user_key(user_key, MASTER_KEY)
        
        # Generate RSA keypair
        public_key, private_key = generate_user_keypair()
        encrypted_private_key = encrypt_private_key(private_key, user_key)
        
        # Buat entitas User dan simpan ke database untuk mendapatkan user_id
        new_user = User(username=username, email=email, encryption_key=encrypted_user_key)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()  # Commit untuk memastikan user_id tersedia

        # Setelah user_id tersedia, buat entitas UserKeys
        user_keys = UserKeys(
            user_id=new_user.id,  # Gunakan new_user.id yang sudah terisi
            public_key=public_key.decode('utf-8'),
            private_key=encrypted_private_key
        )

        db.session.add(user_keys)
        db.session.commit()  # Commit lagi setelah menambahkan UserKeys
        
        flash("Account created successfully", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/choose_user")
def choose_user():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    requester_id = session["user_id"]

    # Ambil semua pengguna yang memiliki permintaan akses 'approved' untuk user yang sedang login
    approved_requests = ShareRequest.query.filter_by(
        requester_id=requester_id,
        status='approved'
    ).all()

    # Dapatkan daftar unique user (owner) berdasarkan permintaan yang disetujui
    owners = {request.owner for request in approved_requests if request.expiry_date >= datetime.utcnow()}
    
    return render_template("choose_user.html", owners=owners)

@app.route("/request_access", methods=["GET", "POST"])
@app.route("/request_access/<int:owner_id>", methods=["GET", "POST"])
def request_access(owner_id=None):
    if "user_id" not in session:
        flash("You need to log in first.", "warning")
        return redirect(url_for("login"))

    requester_id = session["user_id"]

    # Tangani metode GET untuk menampilkan halaman `request_access.html`
    if request.method == "GET":
        return render_template("request_access.html")

    # Tangani metode POST untuk membuat permintaan akses
    owner_id = owner_id or request.form.get("owner_id")  # Dapatkan owner_id dari URL atau form

    # Validasi jika owner_id tidak diisi atau jika pengguna meminta akses ke data mereka sendiri
    if not owner_id or int(owner_id) == requester_id:
        flash("Invalid user ID or you can't request access to your own data.", "danger")
        return redirect(url_for("dashboard"))

    # Cek apakah permintaan sudah ada
    existing_request = ShareRequest.query.filter_by(
        requester_id=requester_id,
        owner_id=owner_id,
        status='pending'
    ).first()

    if existing_request:
        flash("You already have a pending request for this user.", "warning")
        return redirect(url_for("dashboard"))

    # Buat permintaan akses baru
    share_request = ShareRequest(
        requester_id=requester_id,
        owner_id=owner_id,
        request_date=datetime.utcnow(),
        expiry_date=datetime.utcnow() + timedelta(days=7)  # Validitas 7 hari
    )
    
    db.session.add(share_request)
    db.session.commit()
    
    flash("Access request sent successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/manage_requests")
def manage_requests():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user_id = session["user_id"]
    received_requests = ShareRequest.query.filter_by(owner_id=user_id, status='pending').all()
    sent_requests = ShareRequest.query.filter_by(requester_id=user_id).all()
    
    return render_template(
        "manage_requests.html",
        received_requests=received_requests,
        sent_requests=sent_requests
    )

@app.route("/approve_request/<int:request_id>", methods=["POST"])
def approve_request(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    share_request = ShareRequest.query.get_or_404(request_id)
    
    if share_request.owner_id != session["user_id"]:
        flash("Unauthorized action", "danger")
        return redirect(url_for("manage_requests"))
    
    try:
        # Mendapatkan owner key yang didekripsi
        owner = User.query.get(session["user_id"])
        owner_key = decrypt_user_key(owner.encryption_key, MASTER_KEY)
        logging.info(f"Owner Key after decryption: {owner_key}")

        # Enkripsi owner key dengan public key penerima
        requester_keys = UserKeys.query.filter_by(user_id=share_request.requester_id).first()
        encrypted_owner_key = encrypt_sharing_key(owner_key, requester_keys.public_key)
        logging.info(f"Owner Key after re-encryption with requester's public key: {encrypted_owner_key}")
        
        # Simpan key yang telah terenkripsi di permintaan
        share_request.status = 'approved'
        share_request.encrypted_key = encrypted_owner_key
        
        db.session.commit()
        flash("Access request approved and key shared.", "success")
    except Exception as e:
        flash(f"Error processing request: {str(e)}", "danger")
    
    return redirect(url_for("manage_requests"))

@app.route("/reject_request/<int:request_id>", methods=["POST"])
def reject_request(request_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    share_request = ShareRequest.query.get_or_404(request_id)

    if share_request.owner_id != session["user_id"]:
        flash("Unauthorized action", "danger")
        return redirect(url_for("manage_requests"))

    share_request.status = 'rejected'
    db.session.commit()
    
    flash("Request rejected.", "info")
    return redirect(url_for("manage_requests"))


@app.route("/shared_files/<int:owner_id>")
def shared_files(owner_id):
    # Pastikan user telah login
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    requester_id = session["user_id"]

    # Verifikasi apakah pengguna memiliki akses 'approved' untuk file owner yang diminta
    share_request = ShareRequest.query.filter_by(
        requester_id=requester_id,
        owner_id=owner_id,
        status='approved'
    ).first()
    
    if not share_request or share_request.expiry_date < datetime.utcnow():
        flash("You don't have access to these files or your access has expired.", "danger")
        return redirect(url_for("dashboard"))
    
    # Ambil daftar file milik owner
    aes_files = AesFile.query.filter_by(user_id=owner_id).all()
    des_files = DesFile.query.filter_by(user_id=owner_id).all()
    rc4_files = Rc4File.query.filter_by(user_id=owner_id).all()
    
    return render_template(
        "shared_files.html",
        owner_id=owner_id,
        aes_files=aes_files,
        des_files=des_files,
        rc4_files=rc4_files
    )

@app.route("/download_file/<int:file_id>/<encryption_method>/<int:owner_id>")
def download_file(file_id, encryption_method, owner_id):
    logging.info("Starting download file process")

    if "user_id" not in session:
        return redirect(url_for("login"))

    requester_id = session["user_id"]
    share_request = ShareRequest.query.filter_by(
        requester_id=requester_id,
        owner_id=owner_id,
        status='approved'
    ).first()

    if not share_request or share_request.expiry_date < datetime.utcnow():
        flash("You don't have access to this file or your access has expired.", "danger")
        return redirect(url_for("dashboard"))

    try:
        # Ambil private key requester untuk mendekripsi sharing key
        requester = User.query.get(requester_id)
        requester_key = decrypt_user_key(requester.encryption_key, MASTER_KEY)
        user_keys = UserKeys.query.filter_by(user_id=requester_id).first()
        
        private_key = RSA.import_key(decrypt_private_key(user_keys.private_key, requester_key))
        
        # Decrypt sharing key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        owner_key = cipher_rsa.decrypt(base64.b64decode(share_request.encrypted_key))
        logging.info(f"Decrypted owner key used for file decryption: {owner_key}")

        # Pastikan dekripsi file menggunakan key yang benar
        decrypted_data = None
        if encryption_method == "AES":
            encrypted_file = AesFile.query.filter_by(id=file_id, user_id=owner_id).first()
            decrypted_data = decrypt_aes_file_in_chunks(encrypted_file.data_oid, owner_key, encrypted_file.file_size)
        elif encryption_method == "DES":
            encrypted_file = DesFile.query.filter_by(id=file_id, user_id=owner_id).first()
            decrypted_data = decrypt_des_file_in_chunks(encrypted_file.data_oid, owner_key, encrypted_file.file_size)
        elif encryption_method == "RC4":
            encrypted_file = Rc4File.query.filter_by(id=file_id, user_id=owner_id).first()
            decrypted_data = decrypt_rc4_file_in_chunks(encrypted_file.data_oid, owner_key, encrypted_file.file_size)
        
        if not encrypted_file:
            flash("File not found", "danger")
            return redirect(url_for("shared_files", owner_id=owner_id))
            
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=encrypted_file.filename,
            as_attachment=True,
            mimetype=encrypted_file.filetype
        )
    except Exception as e:
        flash(f"Error decrypting file: {str(e)}", "danger")
        logging.error(f"File decryption error: {str(e)}")
        return redirect(url_for("shared_files", owner_id=owner_id))
        
    except Exception as e:
        flash(f"Error decrypting file: {str(e)}", "danger")
        logging.error(f"File decryption error: {str(e)}")
        return redirect(url_for("shared_files", owner_id=owner_id))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Temukan pengguna berdasarkan email
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session.permanent = True
            
            # Dekripsi kunci pengguna (user_key) menggunakan MASTER_KEY dan simpan di sesi
            user_key = decrypt_user_key(user.encryption_key, MASTER_KEY)
            session["user_key"] = user_key  # Simpan user_key di sesi
            
            flash("Login successful", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        encryption_method = request.form.get("encryption")
        file = request.files.get("file")
        user_id = session.get("user_id")

        if not encryption_method or encryption_method == "Choose an encryption method":
            flash("Please select an encryption method", "danger")
            return redirect(url_for("encrypt"))

        if not file:
            flash("No file selected", "danger")
            return redirect(url_for("encrypt"))

        try:
            user = User.query.get(user_id)
            user_key = decrypt_user_key(user.encryption_key, MASTER_KEY)

            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)

            with large_object_cursor() as cursor:
                lo_oid = connection.lobject(0, 'wb').oid
                lo = connection.lobject(lo_oid, mode='wb')
                lo.write(file.read())
                lo.close()

            if encryption_method == "AES":
                encrypted_oid = encrypt_aes_file_in_chunks(lo_oid, user_key, file_size)
                encrypted_file = AesFile(user_id=user_id, filename=file.filename, filetype=file.content_type, data_oid=encrypted_oid, file_size=file_size)
            elif encryption_method == "DES":
                encrypted_oid = encrypt_des_file_in_chunks(lo_oid, user_key, file_size)
                encrypted_file = DesFile(user_id=user_id, filename=file.filename, filetype=file.content_type, data_oid=encrypted_oid, file_size=file_size)
            elif encryption_method == "RC4":
                encrypted_oid = encrypt_rc4_file_in_chunks(lo_oid, user_key, file_size)
                encrypted_file = Rc4File(user_id=user_id, filename=file.filename, filetype=file.content_type, data_oid=encrypted_oid, file_size=file_size)

            db.session.add(encrypted_file)
            db.session.commit()

            flash("File encrypted successfully", "success")
            return redirect(url_for("encrypt"))

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("encrypt"))

    return render_template("encrypt.html")

# Perbaikan untuk fungsi decrypt di route /decrypt

@app.route("/decrypt", methods=["POST", "GET"])
def decrypt():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    owner_id = request.args.get("owner_id", user_id, type=int)
    
    # If accessing another user's files
    if owner_id != user_id:
        share_request = ShareRequest.query.filter_by(
            requester_id=user_id,
            owner_id=owner_id,
            status='approved'
        ).first()
        
        if not share_request or share_request.expiry_date < datetime.utcnow():
            flash("You don't have access to these files", "danger")
            return redirect(url_for("dashboard"))

    aes_files = AesFile.query.filter_by(user_id=owner_id).all()
    des_files = DesFile.query.filter_by(user_id=owner_id).all()
    rc4_files = Rc4File.query.filter_by(user_id=owner_id).all()

    if request.method == "POST":
        try:
            file_id = request.form.get("file_id")
            encryption_method = request.form.get("encryption")
            
            # Get appropriate user key
            if owner_id == user_id:
                user = User.query.get(user_id)
                user_key = decrypt_user_key(user.encryption_key, MASTER_KEY)
            else:
                # Decrypt sharing key using requester's private key
                requester = User.query.get(user_id)
                requester_key = decrypt_user_key(requester.encryption_key, MASTER_KEY)
                user_keys = UserKeys.query.filter_by(user_id=user_id).first()
                private_key = decrypt_private_key(user_keys.private_key, requester_key)
                
                # Decrypt the sharing key
                rsa_key = RSA.import_key(private_key)
                cipher = PKCS1_OAEP.new(rsa_key)
                encrypted_sharing_key = base64.b64decode(share_request.encrypted_key.encode('utf-8'))
                user_key = cipher.decrypt(encrypted_sharing_key)

            # Read and decrypt file based on encryption method
            decrypted_data = None
            filename = None
            filetype = None
            
            if encryption_method == "AES":
                encrypted_file = AesFile.query.filter_by(id=file_id, user_id=owner_id).first()
                if encrypted_file:
                    with large_object_cursor() as cursor:
                        lo = connection.lobject(encrypted_file.data_oid, mode='rb')
                        encrypted_data = lo.read()
                        lo.close()
                        
                        # Decrypt the data
                        nonce = encrypted_data[:16]
                        ciphertext = encrypted_data[16:]
                        cipher = AES.new(user_key, AES.MODE_EAX, nonce=nonce)
                        decrypted_data = cipher.decrypt(ciphertext)
                        filename = encrypted_file.filename
                        filetype = encrypted_file.filetype
                        
            elif encryption_method == "DES":
                encrypted_file = DesFile.query.filter_by(id=file_id, user_id=owner_id).first()
                if encrypted_file:
                    with large_object_cursor() as cursor:
                        lo = connection.lobject(encrypted_file.data_oid, mode='rb')
                        encrypted_data = lo.read()
                        lo.close()
                        
                        # Decrypt the data
                        iv = encrypted_data[:8]
                        ciphertext = encrypted_data[8:]
                        cipher = DES.new(user_key[:8], DES.MODE_CFB, iv=iv)
                        decrypted_data = cipher.decrypt(ciphertext)
                        filename = encrypted_file.filename
                        filetype = encrypted_file.filetype
                        
            elif encryption_method == "RC4":
                encrypted_file = Rc4File.query.filter_by(id=file_id, user_id=owner_id).first()
                if encrypted_file:
                    with large_object_cursor() as cursor:
                        lo = connection.lobject(encrypted_file.data_oid, mode='rb')
                        encrypted_data = lo.read()
                        lo.close()
                        
                        # Decrypt the data
                        cipher = ARC4.new(user_key)
                        decrypted_data = cipher.decrypt(encrypted_data)
                        filename = encrypted_file.filename
                        filetype = encrypted_file.filetype

            if decrypted_data is None or filename is None or filetype is None:
                flash("Error: Could not find or decrypt the file", "danger")
                return redirect(url_for("decrypt"))

            return send_file(
                io.BytesIO(decrypted_data),
                download_name=filename,
                as_attachment=True,
                mimetype=filetype
            )

        except Exception as e:
            flash(f"An error occurred during decryption: {str(e)}", "danger")
            error_logger.error(f"Decryption error: {str(e)}")
            return redirect(url_for("decrypt"))

    return render_template(
        "decrypt.html",
        aes_files=aes_files,
        rc4_files=rc4_files,
        des_files=des_files,
        owner_id=owner_id
    )

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
