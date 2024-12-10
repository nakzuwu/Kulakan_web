from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from models import db
from models.product import Product
from dotenv import load_dotenv
import uuid
import os

# List all user accounts
def listakun():
    # if 'user_id' not in session or session['role'] != 'super_admin':
    #     return redirect(url_for('login'))
    
    dataAkun = User.query.all()  # Fetch all user accounts

    return render_template('superadmin/content/listakun.html', dataAkun=dataAkun)



# Edit user account
def editakun(id):
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        user.nama = request.form['nama']
        user.email = request.form['email']
        user.alamat = request.form['alamat']
        user.role = request.form['role']

        # Optional: Update password if provided
        if request.form['password']:
            user.password = request.form['password']

        db.session.commit()
        flash('Akun berhasil diperbarui!', 'success')
        return redirect(url_for('listakun'))

    return render_template('superadmin/content/editakun.html', user=user)

# Delete user account
def deleteakun(id):
    user = User.query.get_or_404(id)

    # Prevent deleting the currently logged-in super admin account
    if user.id == session['user_id']:
        flash('Anda tidak dapat menghapus akun Anda sendiri!', 'danger')
        return redirect(url_for('listakun'))

    db.session.delete(user)
    db.session.commit()
    flash('Akun berhasil dihapus!', 'success')

    return redirect(url_for('listakun'))
