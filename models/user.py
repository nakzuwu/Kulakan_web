from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=True)
    profile_photo = db.Column(db.String(200), nullable=True)  # Store the filename of the profile photo

    def __init__(self, name, email, password, address=None, profile_photo=None):
        self.name = name
        self.email = email
        self.password = password
        self.address = address
        self.profile_photo = profile_photo