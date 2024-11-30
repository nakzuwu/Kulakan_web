from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Inisialisasi Flask-Mail
mail = Mail(app)

# Inisialisasi Serializer untuk token
s = URLSafeTimedSerializer(app.secret_key)

# Konfigurasi MySQL Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/kulakan'


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'enkajet439@gmail.com'
app.config['MAIL_PASSWORD'] = 'aw'  # Ganti dengan App Password
app.config['MAIL_DEFAULT_SENDER'] = 'enkajet439@gmail.com'


db = SQLAlchemy(app)

# Model Database untuk User
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


# Inisialisasi Database
with app.app_context():
    db.create_all()

# Route untuk halaman utama
@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('index.html', user=session['user_name'])
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Buat token reset password
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            # Kirim email berisi link reset password
            msg = Message('Reset Password', recipients=[email])
            msg.body = f'Klik link berikut untuk reset password Anda: {reset_url}'
            mail.send(msg)

            flash('Instruksi reset password telah dikirim ke email Anda.', 'info')
        else:
            flash('Email tidak ditemukan.', 'danger')
        return redirect(url_for('forgot_password'))
    
    return render_template('auth/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid selama 1 jam
    except (SignatureExpired, BadTimeSignature):
        flash('Link reset password tidak valid atau sudah kedaluwarsa.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        if len(new_password) < 6:
            flash('Password harus minimal 6 karakter.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(new_password)
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = hashed_password
            db.session.commit()
            flash('Password berhasil direset. Silakan login.', 'success')
            return redirect(url_for('login'))

    return render_template('auth/reset_password.html')

# Route untuk registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
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

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('Login berhasil!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email atau password salah.', 'danger')
    
    return render_template('auth/login.html')

# Route untuk logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

@app.route('/test_email')
def test_email():
    try:
        msg = Message('Test Email', recipients=['paangaming123@gmail.com'])
        msg.body = 'This is a test email sent from Flask app.'
        mail.send(msg)
        return "Email sent successfully!"
    except Exception as e:
        return f"Failed to send email: {e}"

@app.route('/frontend/menuproduk')
def menuproduk():
    return render_template('frontend/menuproduk.html')

@app.route("/frontend/produk")
def detail_produk(produk_id):
    # Cari produk berdasarkan ID
    produk = next((p for p in produk_list if p["id"] == produk_id), None)
    if not produk:
        return "Produk tidak ditemukan", 404
    return render_template("detail-produk.html", produk=produk)

@app.route('/frontend/scan')
def scan():
    return render_template('frontend/scan.html')

@app.route('/frontend/setting')
def setting():
    return render_template('frontend/setting.html')

@app.route('/settings/account', methods=['GET', 'POST'])
def account():
    if request.method == 'POST':
        # Ambil data dari form
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Lakukan validasi atau simpan ke database
        # (tambahkan logika sesuai kebutuhan)

        return redirect(url_for('account'))  # Reload halaman setelah perubahan

    return render_template('settings/account.html')

# admin
@app.route('/admin/dashboard')
def dashboard():
    return render_template('admin/content/dashboard.html')

# Route untuk Add Produk
@app.route('/admin/addproduk', methods=['GET', 'POST'])
def add_produk():
    if request.method == 'POST':
        nama_barang = request.form['nama_barang']
        harga = request.form['harga']
        kategori = request.form['kategori']
        stok = request.form['stok']
        deskripsi = request.form['deskripsi']
        # Simpan data ke database atau proses sesuai kebutuhan
        return render_template('success.html', nama_barang=nama_barang)
    return render_template('admin/content/addproduk.html')


# Route untuk Halaman Lain (Tambahkan sesuai kebutuhan)
@app.route('/admin/messages')
def messages():
    return render_template('messages.html')

@app.route('/admin/settings')
def settings():
    return render_template('admin/settings.html')

@app.route('/admin/help')
def help_page():
    return render_template('help.html')


if __name__ == '__main__':
    app.run(debug=True)
