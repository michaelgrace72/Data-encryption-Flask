from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(255), unique=True, nullable=False)
  email = db.Column(db.String(255), unique=True, nullable=False)
  password = db.Column(db.String(255), nullable=False)

  def set_password(self, password):
    self.password = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.password, password)

class AesFile(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  filename = db.Column(db.String(255), nullable=False)
  filetype = db.Column(db.String(255), nullable=False)
  data = db.Column(db.LargeBinary, nullable=False)

class DesFile(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  filename = db.Column(db.String(255), nullable=False)
  filetype = db.Column(db.String(255), nullable=False)
  data = db.Column(db.LargeBinary, nullable=False)
  
class Rc4File(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  filename = db.Column(db.String(255), nullable=False)
  filetype = db.Column(db.String(255), nullable=False)
  data = db.Column(db.LargeBinary, nullable=False)