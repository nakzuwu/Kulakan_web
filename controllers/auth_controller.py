from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from models import db

def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Hash password
        hashed_password = generate_password_hash(password)

        # Cek apakah email sudah terdaftar
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email sudah terdaftar.', 'danger')
            return redirect(url_for('register'))  # Redirect ke halaman registrasi
        else:
            # Buat user baru
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registrasi berhasil. Silakan login.', 'success')
            return redirect(url_for('login'))  # Redirect ke halaman login
    
    # Render halaman registrasi
    return render_template('auth/register.html')
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Cari user berdasarkan email
        user = User.query.filter_by(email=email).first()

        # Validasi user dan password
        if user and check_password_hash(user.password, password):
            # Simpan detail user di session
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role
            flash('Login berhasil!', 'success')

            # Redirect sesuai role
            if user.role == 'super_admin':
                return redirect(url_for('super_admin_dashboard'))
            elif user.role == 'store_admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('home'))

        flash('Email atau password salah.', 'danger')
        return redirect(url_for('login'))  # Redirect ke halaman login
    
    # Render halaman login
    return render_template('auth/login.html')

def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))
