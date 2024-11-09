from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Route untuk halaman registrasi
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Ambil data dari form
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Logika untuk menyimpan data ke database atau validasi bisa ditambahkan di sini

        # Setelah berhasil mendaftar, arahkan pengguna ke halaman sukses atau login
        return redirect(url_for('register_success'))  # misalnya ke halaman sukses

    # Tampilkan halaman registrasi
    return render_template('auth/register.html')

# Route untuk halaman sukses registrasi
@app.route('/register_success')
def register_success():
    return "Registrasi berhasil!"

# Route untuk halaman login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Ambil data dari form login
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Tambahkan logika autentikasi di sini jika diperlukan

        # Setelah login berhasil, arahkan pengguna ke halaman lain
        return redirect(url_for('home'))  # misalnya ke halaman home

    # Tampilkan halaman login
    return render_template('auth/login.html')

# Route untuk halaman lupa password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Logika untuk proses reset password bisa ditambahkan di sini

        return redirect(url_for('password_reset_sent'))

    return render_template('auth/forgot_password.html')

# Route untuk halaman konfirmasi pengiriman reset password
@app.route('/password_reset_sent')
def password_reset_sent():
    return "Instruksi reset password telah dikirim ke email Anda."

@app.route('/admin/dashboard')
def dashboard():
    return render_template('admin/dashboard.html')

@app.route('/admin/addproduk')
def addproduk():
    return render_template('admin/addproduk.html')

@app.route('/frontend/menuproduk')
def menuproduk():
    return render_template('frontend/menuproduk.html')


if __name__ == '__main__':
    app.run(debug=True)
