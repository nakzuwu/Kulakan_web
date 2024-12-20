from flask import Flask
from controllers.chatbot_controller import chatbot_bp
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
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
from controllers import user_controller
from controllers import auth_controller
from controllers import admin_controller
from controllers import chatbot_controller
from controllers import superadmin_controller
from controllers import checkout_controller
import os
import uuid
import jwt 

app = Flask(__name__)
app.secret_key = 'capstonekel7'

mail = Mail(app)

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

app.register_blueprint(chatbot_bp, url_prefix="/api")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'status': 'error', 'message': 'Endpoint tidak ditemukan'}), 404

#Page

@app.route('/')
def home():
    return user_controller.home()

@app.route('/add_review', methods=['POST'])
def add_review():
    return user_controller.add_review()

@app.route('/profile_settings', methods=['GET', 'POST'])
def profile_settings():
    return user_controller.profile_settings()

# @app.route('/api/profile', methods=['GET', 'POST'])
# def profile_settings_api():
#     return user_controller.profile_settings_api()

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

@app.route('/tentang')
def tentang():
    return render_template('/settings/tentang.html')

@app.route('/scan')
def scan():
    return render_template('frontend/scan.html')

@app.route('/keranjang', methods=['GET', 'POST'])
def keranjang():
    return checkout_controller.keranjang()

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    return checkout_controller.add_to_cart(product_id)

@app.route('/update_cart', methods=['POST'])
def update_cart():
    return checkout_controller.update_cart()

@app.route('/process_payment/<float:total>', methods=['GET'])
def process_payment(total):
    return checkout_controller.process_payment(total)

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    return checkout_controller.payment()

@app.route('/riwayat')
def riwayat():
    return render_template('/frontend/riwayat.html')

#auth
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email tidak ditemukan.', 'danger')
            return redirect(url_for('forgot_password'))

        try:
            # Generate JWT token
            token = jwt.encode(
                {"user_id": user.id, "exp": datetime.utcnow() + timedelta(hours=1)},
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send email
            msg = Message('Reset Password', recipients=[email])
            msg.body = f'Klik tautan berikut untuk mereset password Anda: {reset_url}'
            mail.send(msg)  # Use the imported mail object

            flash('Instruksi reset password telah dikirim ke email Anda.', 'info')
        except Exception as e:
            flash(f'Gagal mengirim email: {str(e)}', 'danger')
            app.logger.error(f"Error during email sending: {str(e)}")

        return redirect(url_for('forgot_password'))

    return render_template('auth/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    return auth_controller.reset_password(token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    return auth_controller.register()

@app.route('/login', methods=['GET', 'POST'])
def login():
    return auth_controller.login()

@app.route('/logout')
def logout():
    return auth_controller.logout()

@app.route('/api/register', methods=['POST'])
def registerApi():
    try:
        data = request.get_json()

        # Validasi input
        if not data:
            return jsonify({'message': 'No data provided.', 'status': 'error'}), 400

        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        address = data.get('address', None)
        profile_photo = data.get('profile_photo', 'default.jpg')
        role = data.get('role', 'user')  # Default role adalah 'user'

        # Validasi input yang wajib
        if not all([name, email, password]):
            return jsonify({'message': 'Name, Email, and Password are required!', 'status': 'error'}), 400

        # Cek apakah email sudah terdaftar
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already exists!', 'status': 'error'}), 400

        # Hash password
        hashed_password = generate_password_hash(password)

        # Simpan data user
        user = User(
            name=name,
            email=email,
            password=hashed_password,
            address=address,
            profile_photo=profile_photo,
            role=role
        )

        db.session.add(user)
        db.session.commit()

        # Return response sukses
        return jsonify({
            'message': 'Account created successfully!',
            'status': 'success',
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'address': user.address,
                'profile_photo': user.profile_photo,
                'role': user.role,
            }
        }), 201

    except Exception as e:
        app.logger.error(f"Error during registration: {str(e)}")
        return jsonify({'message': 'An error occurred during registration.', 'status': 'error'}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    return auth_controller.api_login()
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'error': 'Email and password are required.'}), 400
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid email or password.'}), 401
        # Set user session
        session['user_id'] = user.id
        session['user_name'] = user.name
        session['user_role'] = user.role
        response = make_response(jsonify({
            'message': 'Login successful!',
            'role': user.role
        }), 200)
        response.set_cookie('session', session.sid, httponly=True)  # Securely set the session cookie
        return response
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'An error occurred during login.'}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    return auth_controller.api_logout()

#admin

@app.route('/admin/dashboard')
@role_required('store_admin')
def dashboard():
    return admin_controller.dashboard()

@app.route('/admin/addproduk', methods=['GET', 'POST'])
@role_required('store_admin')  # Membatasi akses hanya untuk admin
def addproduk():
    return admin_controller.addproduk()

@app.route('/admin/produk', methods=['GET'])
@role_required('store_admin') 
def listProduk():
    return admin_controller.listProduk()

# Route to edit a product
@app.route('/admin/editproduk/<int:id>', methods=['GET', 'POST'])
@role_required('store_admin')
def editProduk(id):
    return admin_controller.editProduk(id)

# Route to delete a product
@app.route('/admin/deleteproduk/<int:id>', methods=['POST'])
@role_required('store_admin')
def deleteProduk(id):
    return admin_controller.deleteProduk(id)

@app.route('/superadmin/listakun', methods=['GET'])
@role_required('super_admin')
def listakun():
    return superadmin_controller.listakun()

@app.route('/superadmin/editakun/<int:id>', methods=['GET', 'POST'])
@role_required('super_admin')
def editakun(id):
    return superadmin_controller.editakun(id)

@app.route('/superadmin/deleteakun/<int:id>', methods=['POST'])
@role_required('super_admin')
def deleteakun(id):
    return superadmin_controller.deleteakun(id)

@app.route('/superadmin/produk', methods=['GET'])
@role_required('super_admin') 
def listallProduk():
    return superadmin_controller.listProduk()

@app.route('/superadmin/sentimen', methods=['GET', 'POST'])
@role_required('super_admin')
def sentimen():
    return superadmin_controller.sentimen()

@app.route('/query', methods=['POST'])
def query():
    return chatbot_controller.chat()
  
if __name__ == '__main__':
    app.run(debug=True)