from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from models import db
from models.product import Product
from dotenv import load_dotenv
import uuid
import os

ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def listakun():
    user_id = session.get('user_id')
    super_admin = User.query.get(user_id)

    # Cek apakah user adalah super admin
    if super_admin and super_admin.role == 'super_admin':
        dataAkun = User.query.all()  # Ambil semua data user
        return render_template('superadmin/content/listakun.html', super_admin=super_admin, dataAkun=dataAkun)
    
    flash("You do not have permission to access this page.", "danger")
    return redirect(url_for('login'))


def editakun(id):
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        # Perbarui data akun dari form
        user.name = request.form.get('name', user.name)
        user.email = request.form.get('email', user.email)
        user.address = request.form.get('address', user.address)
        user.role = request.form.get('role', user.role)

        # Perbarui password jika disediakan
        new_password = request.form.get('password')
        if new_password:
            user.password = generate_password_hash(new_password)

        # Periksa jika ada file gambar diunggah
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()  # Ekstensi file
                filename = f"{uuid.uuid4().hex}.{ext}"  # Buat nama file unik
                upload_folder = current_app.config['UPLOAD_FOLDER']
                filepath = os.path.join(upload_folder, filename)
                
                # Simpan file
                file.save(filepath)

                # Hapus foto lama jika ada
                if user.profile_photo and os.path.exists(os.path.join(upload_folder, user.profile_photo)):
                    os.remove(os.path.join(upload_folder, user.profile_photo))

                # Perbarui URL foto profil di database
                user.profile_photo = filename

        # Simpan perubahan ke database
        try:
            db.session.commit()
            flash('Akun berhasil diperbarui!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan saat memperbarui akun: {str(e)}', 'danger')

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
