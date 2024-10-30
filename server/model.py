from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.postgresql import OID
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=False)

    # Relationship to UserKeys, AesFile, DesFile, Rc4File, and ShareRequest models
    user_keys = db.relationship('UserKeys', backref='user', cascade='all, delete', lazy=True)
    aes_files = db.relationship('AesFile', backref='user', cascade='all, delete', lazy=True)
    des_files = db.relationship('DesFile', backref='user', cascade='all, delete', lazy=True)
    rc4_files = db.relationship('Rc4File', backref='user', cascade='all, delete', lazy=True)
    requests_made = db.relationship('ShareRequest', foreign_keys='ShareRequest.requester_id', backref='requester', lazy=True)
    requests_received = db.relationship('ShareRequest', foreign_keys='ShareRequest.owner_id', backref='owner', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f"<User {self.username}>"

class AesFile(db.Model):
    __tablename__ = 'aes_file'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(255), nullable=False)
    data_oid = db.Column(db.Integer, nullable=False)  # OID for large object handling in PostgreSQL
    file_size = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<AesFile {self.filename} for User ID {self.user_id}>"

class DesFile(db.Model):
    __tablename__ = 'des_file'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(255), nullable=False)
    data_oid = db.Column(db.Integer, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<DesFile {self.filename} for User ID {self.user_id}>"

class Rc4File(db.Model):
    __tablename__ = 'rc4_file'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(255), nullable=False)
    data_oid = db.Column(db.Integer, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<Rc4File {self.filename} for User ID {self.user_id}>"

class ShareRequest(db.Model):
    __tablename__ = 'share_request'
    
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime)
    access_expiry = db.Column(db.DateTime)  # Batas waktu akses setelah disetujui
    encrypted_key = db.Column(db.Text, nullable=True)
    is_blocked = db.Column(db.Boolean, default=False)  # Penanda apakah akses diblokir
    is_access_revoked = db.Column(db.Boolean, default=False) 

    def __repr__(self):
        return f"<ShareRequest {self.id} from {self.requester_id} to {self.owner_id} status {self.status}>"

class UserKeys(db.Model):
    __tablename__ = 'user_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)  # Will be encrypted with user's master key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<UserKeys for User ID {self.user_id}>"

class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # e.g., "upload", "download", "share"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    details = db.Column(db.Text)  # Additional details like file name or shared user
    
    def __repr__(self):
        return f"<ActivityLog {self.activity_type} by {self.user_id}>"