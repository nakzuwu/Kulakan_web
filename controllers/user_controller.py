from flask import render_template, request, redirect, url_for, session, flash, current_app, jsonify
from models.user import User
from models import db
from form import ProfileForm
import os
import uuid


ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_from_session():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        return user
    return None

def home():
    user = get_user_from_session()
    if user:
        return render_template('index.html', user=user)
    return redirect(url_for('login'))


# Route untuk forgot password
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


# Route untuk reset password
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

        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                # Generate a unique filename using UUID
                ext = file.filename.rsplit('.', 1)[1].lower()  # Get file extension
                filename = f"{uuid.uuid4().hex}.{ext}"  # Create unique filename
                file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

            if len(new_password) < 6:
                flash('Password harus minimal 6 karakter.', 'danger')
                return redirect(url_for('reset_password', token=token))

            # Hash and update the user's password
            user.password = generate_password_hash(new_password)
            db.session.commit()

            flash('Password berhasil diubah. Silakan login.', 'success')
            return redirect(url_for('login'))

        return render_template('auth/reset_password.html', token=token)

def profile_settings_api():
    # Ensure user is logged in (check if user_id is in session)
    if 'user_id' not in session:
        return jsonify({'message': 'You need to log in first.'}), 403

    # Get user from the database using the user_id from session
    user = User.query.get(session['user_id'])

    if not user:
        return jsonify({'message': 'User not found.'}), 404

    if request.method == 'GET':
        # Return current profile data as JSON
        return jsonify({
            'name': user.name,
            'email': user.email,
            'address': user.address,
            'profile_photo': user.profile_photo or None
        })

    if request.method == 'POST':
        # Get the data from the request body (JSON)
        name = request.json.get('name')
        email = request.json.get('email')
        address = request.json.get('address')

        # Update user details
        if name:
            user.name = name
        if email:
            user.email = email
        if address:
            user.address = address

        # Handle profile photo upload (if any)
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                # Generate a unique filename using UUID
                ext = file.filename.rsplit('.', 1)[1].lower()  # Get file extension
                filename = f"{uuid.uuid4().hex}.{ext}"  # Create unique filename
                filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # Update user's profile_photo in the database
                user.profile_photo = filename

        # Commit changes to the database
        db.session.commit()

        return jsonify({'message': 'Profile updated successfully!'}), 200
