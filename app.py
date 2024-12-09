from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_session import Session
from functools import wraps
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
from controllers import checkout_controller
import os
import jwt

app = Flask(__name__)
app.secret_key = 'capstonekel7'

s = URLSafeTimedSerializer(app.secret_key)

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
app.config['SESSION_TYPE'] = 'filesystem'  # Use file system to store sessions
app.config['SESSION_PERMANENT'] = False    # Sessions are not permanent
app.config['SESSION_USE_SIGNER'] = True    # Use a signed session cookie
app.config['SESSION_KEY_PREFIX'] = 'myapp_'  # Prefix for session keys
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expires in 1 hour
Session(app)

mail = Mail(app)

db.init_app(app)
with app.app_context():
    db.create_all()

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

@app.route('/profile_settings', methods=['GET', 'POST'])
def profile_settings():
    return user_controller.profile_settings()

@app.route('/api/profile', methods=['GET', 'POST'])
def profile_settings_api():
    return user_controller.profile_settings_api()

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

@app.route('/keranjang', methods=['GET', 'POST'])
def keranjang():
    return checkout_controller.keranjang()

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    return checkout_controller.add_to_cart(product_id)

@app.route('/update_cart', methods=['POST'])
def update_cart():
    return checkout_controller.update_cart()

@app.route('/payment')
def payment():
    return render_template('frontend/payment.html')

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
def api_register():
    return auth_controller.api_register()

@app.route('/api/login', methods=['POST'])
def api_login():
    return auth_controller.api_login()

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

if __name__ == '__main__':
    app.run(debug=True)