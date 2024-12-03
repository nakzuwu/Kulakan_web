from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from form import ProfileForm
from models import db
from models.user import User
from models.product import Product
from dotenv import load_dotenv
import os
import uuid
import jwt 

app = Flask(__name__)
app.secret_key = 'capstonekel7'

# Inisialisasi Flask-Mail
mail = Mail(app)

# Inisialisasi Serializer untuk token
s = URLSafeTimedSerializer(app.secret_key)

# Load .env file
load_dotenv()

# Access environment variables
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

# Other configurations
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')


db.init_app(app)
with app.app_context():
    db.create_all()

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
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

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                token = jwt.encode(
                    {
                        "user_id": user.id,
                        "exp": datetime.utcnow() + timedelta(hours=1)
                    },
                    app.config['SECRET_KEY'], algorithm='HS256'
                )

                # Generate the password reset link
                reset_url = url_for('reset_password', token=token, _external=True)

                # Send reset password email
                msg = Message('Reset Password', recipients=[email])
                msg.body = f'Klik tautan berikut untuk mereset password Anda: {reset_url}'
                mail.send(msg)

                flash('Instruksi reset password telah dikirim ke email Anda.', 'info')
            except Exception as e:
                flash(f'Gagal mengirim email: {str(e)}', 'danger')
        else:
            flash('Email tidak ditemukan.', 'danger')
        return redirect(url_for('forgot_password'))
    
    return render_template('auth/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode JWT token to extract user ID
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])

        if not user:
            flash('Token tidak valid atau telah kadaluarsa.', 'danger')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            new_password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            # Validate password match and length
            if not new_password or new_password != confirm_password:
                flash('Password tidak cocok atau kosong.', 'danger')
                return redirect(url_for('reset_password', token=token))

            if len(new_password) < 6:
                flash('Password harus minimal 6 karakter.', 'danger')
                return redirect(url_for('reset_password', token=token))

            # Hash and update the user's password
            user.password = generate_password_hash(new_password)
            db.session.commit()

            flash('Password berhasil diubah. Silakan login.', 'success')
            return redirect(url_for('login'))

        return render_template('auth/reset_password.html', token=token)

    except jwt.ExpiredSignatureError:
        flash('Token telah kadaluarsa.', 'danger')
        return redirect(url_for('forgot_password'))
    except jwt.InvalidTokenError:
        flash('Token tidak valid.', 'danger')
        return redirect(url_for('forgot_password'))


@app.route('/test_email')
def test_email():
    try:
        msg = Message('Test Email', recipients=['paangaming123@gmail.com'])
        msg.body = 'This is a test email sent from Flask app.'
        mail.send(msg)
        return "Email sent successfully!"
    except Exception as e:
        return f"Failed to send email: {e}"

    
# Route untuk registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email' )
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)

        # Cek apakah email sudah terdaftar
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email sudah terdaftar.', 'danger')
        else:
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registrasi berhasil. Silakan login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/register.html')

# Route untuk login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Cari user berdasarkan email
        user = User.query.filter_by(email=email).first()

        # Verifikasi password
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role  # Menyimpan role pengguna di session

            flash('Login berhasil!', 'success')

            # Redirect berdasarkan role
            if user.role == 'super_admin':
                return redirect(url_for('super_admin_dashboard'))  # Halaman untuk super admin
            elif user.role == 'store_admin':
                return redirect(url_for('store_admin_dashboard'))  # Halaman untuk store admin
            else:
                return redirect(url_for('home'))  # Halaman untuk user biasa

        else:
            flash('Email atau password salah.', 'danger')
    
    return render_template('auth/login.html')

# Route untuk logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

@app.route('/profile_settings', methods=['GET', 'POST'])
def profile_settings():
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    form = ProfileForm()

    if form.validate_on_submit():
        # Update user details
        user.name = form.name.data
        user.email = form.email.data
        user.address = form.address.data

        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                # Generate a unique filename using UUID
                ext = file.filename.rsplit('.', 1)[1].lower()  # Get file extension
                filename = f"{uuid.uuid4().hex}.{ext}"  # Create unique filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Update user's profile_photo in the database
                user.profile_photo = filename

        # Save other updates to the database
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile_settings'))

    # Prepopulate the form with current data
    form.name.data = user.name
    form.email.data = user.email
    form.address.data = user.address

    return render_template('profile_settings.html', form=form, user=user)

# API untuk Register
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()  # Mendapatkan data JSON dari body request
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'status': 'error', 'message': 'Semua field harus diisi'}), 400

    # Hash password
    hashed_password = generate_password_hash(password)

    # Cek apakah email sudah terdaftar
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'status': 'error', 'message': 'Email sudah terdaftar'}), 400

    # Simpan pengguna baru
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Registrasi berhasil'}), 201

# API untuk Login
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()  # Mendapatkan data JSON dari body request
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Email dan password harus diisi'}), 400

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        # Generate token untuk otentikasi
        payload = {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)  # Token akan kadaluarsa dalam 24 jam
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

        # Decode token ke dalam format string (untuk dikirim dalam response)
        return jsonify({
            'status': 'success',
            'message': 'Login berhasil',
            'token': token.decode('utf-8')  # Decode hasil token menjadi string UTF-8
        }), 200

    return jsonify({'status': 'error', 'message': 'Email atau password salah'}), 401
# API untuk Logout
@app.route('/api/logout', methods=['POST'])
def api_logout():
    # Logout tidak memerlukan penanganan di backend jika menggunakan token-based auth
    return jsonify({'status': 'success', 'message': 'Logout berhasil'}), 200

# API untuk Mendapatkan Data User
@app.route('/api/user', methods=['GET'])
def api_get_user():
    # Token harus dikirim melalui header Authorization
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'status': 'error', 'message': 'Token tidak diberikan'}), 401

    try:
        # Decode token untuk mendapatkan user ID
        data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user = User.query.get(data['user_id'])

        if not user:
            return jsonify({'status': 'error', 'message': 'User tidak ditemukan'}), 404

        # Return data pengguna
        return jsonify({
            'status': 'success',
            'data': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'address': user.address,
                'profile_photo': user.profile_photo
            }
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'error', 'message': 'Token telah kadaluarsa'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'status': 'error', 'message': 'Token tidak valid'}), 401
    
# Error Handler untuk 404
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'status': 'error', 'message': 'Endpoint tidak ditemukan'}), 404

def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check if user is logged in
            if 'user_id' not in session:
                flash("You need to log in to access this page.", "warning")
                return redirect(url_for('login'))
            
            # Fetch the user object (adjust based on your user model)
            user = User.query.get(session['user_id'])
            if not user or user.role != role:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('home'))
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/admin/content/dashboard')
@role_required('store_admin')
def dashboard():
    # Get the currently logged-in admin
    user_id = session.get('user_id')
    admin = User.query.get(user_id)

    if admin and admin.role == 'store_admin':
        # Fetch products associated with this admin
        products = Product.query.filter_by(user_id=admin.id).all()
        return render_template('admin/content/dashboard.html', admin=admin, products=products)
    
    flash("You do not have permission to access this page.", "danger")
    return redirect(url_for('home'))

# Route untuk form tambah produk
@app.route('/addproduk', methods=['GET', 'POST'])
@role_required('store_admin')  # Membatasi akses hanya untuk admin
def addproduk():
    if request.method == 'POST':
        nama_barang = request.form['nama_barang']
        harga = request.form['harga']
        kategori = request.form['kategori']
        stok = request.form['stok']
        deskripsi = request.form['deskripsi']

        # Mendapatkan file gambar
        file = request.files['gambar']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        else:
            flash('Format file tidak didukung!', 'error')
            return redirect(request.url)

        # Mendapatkan user_id dari session
        user_id = session.get('user_id')
        if not user_id:
            flash('Anda harus login untuk menambahkan produk!', 'error')
            return redirect(url_for('login'))

        # Validasi dan tambah produk ke database
        produk_baru = Product(
            nama_barang=nama_barang,
            harga=int(harga),
            kategori=kategori,
            stok=int(stok),
            deskripsi=deskripsi,
            gambar=filename,
            user_id=user_id  # Menghubungkan produk dengan admin saat ini
        )
        try:
            db.session.add(produk_baru)
            db.session.commit()
            flash('Produk berhasil ditambahkan!', 'success')
            return redirect(url_for('addproduk'))
        except Exception as e:
            flash(f'Terjadi kesalahan: {e}', 'error')

    return render_template('admin/content/addproduk.html')

with app.app_context():
    db.create_all()
# addproduk

# edit

# edit
@app.route('/frontend/detailproduk/<int:id>')
def detailProduk(id):
    dataBs = Product.query.get_or_404(id)
    return render_template('frontend/detailproduk.html', dataBs=dataBs)
@app.route('/frontend/menuproduk')
def menuproduk():
    dataProduk = Product.query.all()
    return render_template('frontend/menuproduk.html', dataProduk=dataProduk)

@app.route('/setting')
def setting():
    return render_template('frontend/setting.html')

@app.route('/scan')
def scan():
    return render_template('frontend/scan.html')

if __name__ == '__main__':
    app.run(debug=True)
