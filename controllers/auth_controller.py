import os
import uuid
from flask import render_template, session, redirect, url_for, request, current_app
from models.user import User
from app import db
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from form import ProfileForm
from models import db
from models.user import User
from models.product import Produk
from dotenv import load_dotenv
from controllers.auth_controller import *
import os
import uuid
import jwt 

ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                # Generate a unique filename using UUID
                ext = file.filename.rsplit('.', 1)[1].lower()  # Get file extension
                filename = f"{uuid.uuid4().hex}.{ext}"  # Create unique filename
                file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

                # Update user's profile_photo in the database
                user.profile_photo = filename
                db.session.commit()  # Commit changes to the database
        return render_template('index.html', user=user)  # Kirim objek user ke template
    return redirect(url_for('login'))