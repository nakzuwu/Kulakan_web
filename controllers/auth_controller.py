import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from models import db


def validate_email(email):
    # Email regex pattern to match valid email addresses
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def validate_password(password):
    # Password must be at least 8 characters long, contain at least one uppercase letter, and one digit
    password_regex = r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$'
    return re.match(password_regex, password)

def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)

        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('auth/register.html')

        # Validate password
        if not validate_password(password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, and one digit.', 'danger')
            return render_template('auth/register.html')

        # Check if the email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
        else:
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/register.html')

def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Email validation
        if not validate_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('auth/login.html')

        # Password validation
        if not validate_password(password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, and one digit.', 'danger')
            return render_template('auth/login.html')

        # Find user by email
        user = User.query.filter_by(email=email).first()

        # Verify password
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role  # Store user role in session

            flash('Login successful!', 'success')

            # Redirect based on role
            if user.role == 'super_admin':
                return redirect(url_for('super_admin_dashboard'))  # Dashboard for super admin
            elif user.role == 'store_admin':
                return redirect(url_for('dashboard'))  # Dashboard for store admin
            else:
                return redirect(url_for('home'))  # Dashboard for regular user

        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('auth/login.html')

def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))