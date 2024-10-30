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
import time
import io
from model import db, User, Rc4File, AesFile, DesFile
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from config import Config
import os
import logging

# Setup logging for performance tracking (log only performance, not requests)
logging.basicConfig(filename='encryption_performance.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# Disable Flask's default request logging to avoid logging HTTP requests
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)  # This will silence the HTTP request logs

# Setup separate logging for error tracking
error_logger = logging.getLogger('error_logger')
error_handler = logging.FileHandler('error.log')
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
error_logger.addHandler(error_handler)

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
app.config["UPLOAD_FOLDER"] = "uploads/"

@app.before_request
def before_request():
    g.current_page = None

# Context processor to inject username into all templates
@app.context_processor
def inject_user():
    user_id = session.get("user_id")

    if user_id:
        user = User.query.get(user_id)
        if user:
            return {"username": user.username}
    return {}

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

# Encrypt DES file using CFB mode
def encrypt_des_file_in_cfb(file_path, key, block_size=1024):
    cipher = DES.new(key[:8], DES.MODE_CFB)  # Menggunakan CFB
    encrypted_data = bytearray()
    with open(file_path, "rb") as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            encrypted_data += cipher.encrypt(block)

    return cipher.iv + encrypted_data

# Decrypt DES file using CFB mode
def decrypt_des_file_in_cfb(encrypted_data, key, block_size=1024):
    iv = encrypted_data[:8]
    encrypted_data = encrypted_data[8:]
    cipher = DES.new(key[:8], DES.MODE_CFB, iv=iv)
    decrypted_data = bytearray()

    for i in range(0, len(encrypted_data), block_size):
        block = encrypted_data[i:i + block_size]
        decrypted_data += cipher.decrypt(block)

    return decrypted_data

# General function to encrypt a file based on the method
def encrypt_file(file_path, encryption_method, key):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        start_time = time.time()  # Record the start time
        encrypted_data = None
        if encryption_method == "AES":
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted_data = cipher.nonce + tag + ciphertext
        elif encryption_method == "DES":
            encrypted_data = encrypt_des_file_in_cfb(file_path, key[:8])  # Modifikasi untuk CFB
        elif encryption_method == "RC4":
            cipher = ARC4.new(key)
            encrypted_data = cipher.encrypt(data)

        end_time = time.time()  # Record the end time
        encryption_time = end_time - start_time  # Calculate encryption time

        # Log performance: encryption method, file size, and encryption time
        file_size = os.path.getsize(file_path)
        encrypted_file_size = len(encrypted_data)

        logging.info(f"Method: {encryption_method}, Original Size: {file_size} bytes, "
                     f"Encrypted Size: {encrypted_file_size} bytes, Time: {encryption_time:.6f} seconds")

        return encrypted_data, encryption_time

    except Exception as e:
        error_logger.error(f"Error encrypting file '{file_path}' using {encryption_method}. Error: {str(e)}")
        raise  # Re-raise the error after logging it

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        encryption_method = request.form.get("encryption")
        file = request.files.get("file")
        user_id = session.get("user_id")

        if (encryption_method == "Choose an encryption method" or not encryption_method):
            flash("Please select an encryption method", "danger")
            return redirect(url_for("encrypt"))

        if not file:
            flash("No file selected", "danger")
            return redirect(url_for("encrypt"))

        try:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(file_path)
            user = User.query.get(user_id)
            encrypted_data, encryption_time = encrypt_file(
                file_path, encryption_method, user.encryption_key
            )

            # Log the performance (time and file size)
            logging.info(f"User {user_id} encrypted file '{file.filename}' using {encryption_method} "
                         f"in {encryption_time:.6f} seconds.")

            # Save the encrypted file to the database
            if encryption_method == "AES":
                encrypted_file = AesFile(
                    user_id=user_id,
                    filename=file.filename,
                    filetype=file.content_type,
                    data=encrypted_data,
                )
            elif encryption_method == "DES":
                encrypted_file = DesFile(
                    user_id=user_id,
                    filename=file.filename,
                    filetype=file.content_type,
                    data=encrypted_data,
                )
            elif encryption_method == "RC4":
                encrypted_file = Rc4File(
                    user_id=user_id,
                    filename=file.filename,
                    filetype=file.content_type,
                    data=encrypted_data,
                )

            db.session.add(encrypted_file)
            db.session.commit()

            # Delete the file after encryption
            os.remove(file_path)

            flash(
                f"File encrypted successfully in {encryption_time:.4f} seconds",
                "success",
            )
            return redirect(url_for("encrypt"))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("encrypt"))

    return render_template("encrypt.html", current_page="Encrypt")

# General function to decrypt a file based on the method
def decrypt_file(encrypted_data, key, encryption_method):
    if encryption_method == "AES":
        nonce, tag, ciphertext = (
            encrypted_data[:16],
            encrypted_data[16:32],
            encrypted_data[32:],
        )
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

    elif encryption_method == "DES":
        data = decrypt_des_file_in_cfb(encrypted_data, key[:8])  # Modifikasi untuk CFB

    elif encryption_method == "RC4":
        cipher = ARC4.new(key)
        data = cipher.decrypt(encrypted_data)

    return data

@app.route("/decrypt", methods=["POST", "GET"])
def decrypt():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session.get("user_id")

    aes_files = AesFile.query.filter_by(user_id=user_id).all()
    des_files = DesFile.query.filter_by(user_id=user_id).all()
    rc4_files = Rc4File.query.filter_by(user_id=user_id).all()

    if request.method == "POST":
        user_id = session.get("user_id")
        file_id = request.form.get("file_id")
        encryption_method = request.form.get("encryption")
        print(file_id)

        user = User.query.get(user_id)

        # Retrieve the encrypted file from the database
        if encryption_method == "AES":
            encrypted_file = AesFile.query.filter_by(
                id=file_id, user_id=user_id
            ).first()
        elif encryption_method == "DES":
            encrypted_file = DesFile.query.filter_by(
                id=file_id, user_id=user_id
            ).first()
        elif encryption_method == "RC4":
            encrypted_file = Rc4File.query.filter_by(
                id=file_id, user_id=user_id
            ).first()

        if not encrypted_file:
            flash("File not found.", "danger")
            return redirect(url_for("decrypt"))

        decrypted_data = decrypt_file(
            encrypted_file.data, user.encryption_key, encryption_method
        )

        return send_file(
            io.BytesIO(decrypted_data),
            download_name=encrypted_file.filename,
            as_attachment=True,
            mimetype=encrypted_file.filetype,
        )

    return render_template(
        "decrypt.html",
        current_page="Decrypt",
        aes_files=aes_files,
        rc4_files=rc4_files,
        des_files=des_files,
    )

@app.route("/register", methods=["GET", "POST"])
def register():
    # if the request is a POST request, then the user has submitted the form
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # check if the user already exist
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email address already exists", "warning")
            return redirect(url_for("register"))

        # create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        new_user.encryption_key = get_random_bytes(16)

        db.session.add(new_user)
        db.session.commit()  # save the user to the database
        flash("Account created successfully", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # authenticate the user
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # store the user's id in the session
            session["user_id"] = user.id
            session.permanent = True  # this makes the session last for the set lifetime

            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()  # clear session data
    return redirect(url_for("home"))

if __name__ == "__main__":
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(debug=True, port=5001)
