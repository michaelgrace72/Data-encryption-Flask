from flask import Flask, render_template, request, jsonify, url_for, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from usersmodel import db, User
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/dashboard')
def dashboard():
    # check i fuser logged in
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('home'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html')

@app.route('/aes-encryption', methods=['GET','POST'])
def aes_encryption():
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('home'))
    return render_template('AES_encrypt.html')

@app.route('/aes-decryption/', methods=['GET'])
def aes_decryption():
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('home'))
    return render_template('AES_decrypt.html')

@app.route('/des-encryption', methods=['GET','POST'])
def des_encryption():
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('home'))
    return render_template('DES_encrypt.html')

@app.route('/des-decryption', methods=['GET','POST'])
def des_decryption():
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('home'))
    return render_template('DES_decrypt.html')

@app.route('/rc4-encryption', methods=['GET','POST'])
def rc4_encryption():
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('home'))
    return render_template('RC4_encrypt.html')

@app.route('/rc4-decryption', methods=['GET','POST'])
def rc4_decryption():
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('home'))
    return render_template('RC4_decrypt.html')

@app.route('/register', methods=['GET','POST'])
def register():
    #if the request is a POST request, then the user has submitted the form
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # check if the user already exist
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists', 'warning')
            return redirect(url_for('register'))
        
        # create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit() # save the user to the database
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # authenticate the user
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # store the user's id in the session
            session['user_id'] = user.id
            session.permanent = True # this makes the session last for the set lifetime
            
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear() # clear session data
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001) 