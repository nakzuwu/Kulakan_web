from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from form import ProfileForm
from models import db
from models.product import Product
from dotenv import load_dotenv
from controllers import user_controller
from controllers import auth_controller
from flask_bcrypt import Bcrypt
import os
import uuid
import jwt 

app = Flask(__name__)
app.secret_key = 'capstonekel7'

mail = Mail(app)

bcrypt = Bcrypt(app)

from models.user import User
# Inisialisasi Serializer untuk token
s = URLSafeTimedSerializer(app.secret_key)

# Load .env file
# Inisialisasi Flask-Mail
load_dotenv()

# Access environment variables
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

# Other configurations
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/db_kulakan?ssl_disabled=false'

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
    return user_controller.home()

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

# Route untuk registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    return auth_controller.register()

# Route untuk login
@app.route('/login', methods=['GET', 'POST'])
def login():
    return auth_controller.login()

@app.route('/api/login', methods=['POST'])
def loginApi():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Email atau Password Salah!', 'status': 'danger'}), 401



    return jsonify({
        'message': 'Login berhasil!',
        'status': 'success',
        'user': {
            "id": user.id,
            "email": user.email
            }
    }), 200

# Route untuk logout
@app.route('/logout')
def logout():
    return auth_controller.logout()

# Route untuk profile user setting
@app.route('/profile_settings', methods=['GET', 'POST'])
def profile_settings():
    return user_controller.profile_settings()

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
        if 'gambar' in request.files:
            file = request.files['gambar']
            if file and allowed_file(file.filename):
                # Generate a unique filename using UUID
                ext = file.filename.rsplit('.', 1)[1].lower()  # Get file extension
                filename = f"{uuid.uuid4().hex}.{ext}"  # Create unique filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
            else:
                flash('Format file tidak didukung!', 'error')
                return redirect(request.url)
        else:
            flash('File gambar wajib diunggah!', 'error')
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
            gambar=filename,  # Menyimpan hanya nama file di database
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

@app.route('/admin/produk', methods=['GET'])
def listProduk():
    # Ensure the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if user is not logged in

    # Fetch the user from the session
    user = User.query.get(session['user_id'])

    # Fetch only products that belong to the logged-in user
    dataProduk = Product.query.filter_by(user_id=user.id).all()

    # Return the filtered products to the template
    return render_template('admin/content/listproduk.html', dataProduk=dataProduk)

# Route to edit a product
@app.route('/admin/editproduk/<int:id>', methods=['GET', 'POST'])
def editProduk(id):
    product = Product.query.get_or_404(id)

    if request.method == 'POST':
        # Get updated values from the form
        product.nama_barang = request.form['nama_barang']
        product.harga = request.form['harga']
        product.kategori = request.form['kategori']
        product.stok = request.form['stok']
        product.deskripsi = request.form['deskripsi']

        # Handle file upload for product image (if necessary)
        if 'gambar' in request.files:
            gambar = request.files['gambar']
            if gambar:
                gambar_path = 'path/to/save/image'  # Adjust this path to your requirements
                gambar.save(gambar_path)
                product.gambar = gambar_path

        # Commit the changes to the database
        db.session.commit()
        flash('Produk berhasil diperbarui!', 'success')
        return redirect(url_for('listProduk'))  # Redirect to the product list

    # Display the edit form with current product data
    return render_template('admin/content/editproduk.html', product=product)

# Route to delete a product
@app.route('/admin/deleteproduk/<int:id>', methods=['POST'])
def deleteProduk(id):
    product = Product.query.get_or_404(id)

    # Delete the product
    db.session.delete(product)
    db.session.commit()
    flash('Produk berhasil dihapus!', 'success')

    return redirect(url_for('listProduk'))  # Redirect to the product list

with app.app_context():
    db.create_all()

# edit
@app.route('/detailproduk/<int:id>')
def detailProduk(id):
    dataBs = Product.query.get_or_404(id)
    return render_template('frontend/detailproduk.html', dataBs=dataBs)

@app.route('/menuproduk')
def menuproduk():
    dataProduk = Product.query.all()
    return render_template('frontend/menuproduk.html', dataProduk=dataProduk)

@app.route('/setting')
def setting():
    return render_template('frontend/setting.html')

@app.route('/scan')
def scan():
    return render_template('frontend/scan.html')

@app.route('/keranjang')
def keranjang():
    return render_template('frontend/keranjang.html')

@app.route('/payment')
def payment():
    return render_template('frontend/payment.html')

if __name__ == '__main__':
    app.run(debug=True)
