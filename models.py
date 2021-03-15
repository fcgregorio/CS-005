from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime, timedelta


db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), unique=False, nullable=False)
    last_name = db.Column(db.String(50), unique=False, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    password_updated_at = db.Column(db.TIMESTAMP(), unique=False, nullable=False)
    password_history = db.Column(db.PickleType(), unique=False, nullable=False)
    login_attempt_history = db.Column(db.PickleType(), unique=False, nullable=False)

    messages = db.relationship('Message', backref='user', lazy=True)

    def __init__(self, first_name, last_name, username, email, password):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
        self.password_updated_at = datetime.now()
        self.password_history = []
        self.login_attempt_history = []

    def verify_password(self, pwd):
        return check_password_hash(self.password, pwd)

    def is_password_almost_expired(self):
        return self.password_updated_at + timedelta(days=20) < datetime.now()

    def is_password_expired(self):
        return self.password_updated_at + timedelta(days=30) < datetime.now()

    def password_expire_days(self):
        duration = self.password_updated_at + timedelta(days=30) - datetime.now()
        return duration.days


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), unique=False, nullable=False)
    created_at = db.Column(db.TIMESTAMP(), unique=False, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, content):
        self.content = content
        self.created_at = datetime.now()


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    object_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('subject_user_id', 'object_user_id'),
    )