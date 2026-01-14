from PIL import Image, ImageDraw, ImageFilter, ImageFont
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import io
import os
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['SECRET_KEY'] = 'kunci-rahasia-anda-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Konfigurasi Email (Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'yannzzz13@gmail.com'
app.config['MAIL_PASSWORD'] = 'zhqy klci ywud pvnm'
app.config['MAIL_DEFAULT_SENDER'] = 'yannzzz13@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False

db = SQLAlchemy(app)
mail = Mail(app)

# Model Database User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(32))
    email_otp_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Model untuk Log Aktivitas
class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    status = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

# Model untuk menyimpan OTP Email sementara
class EmailOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

# Buat database
with app.app_context():
    db.create_all()

# Fungsi untuk generate slider captcha
def generate_slider_captcha():
    """Generate slider captcha yang mudah divalidasi"""
    width = 300
    height = 150
    piece_size = 50
    
    target_x = 150
    target_y = random.randint(30, height - piece_size - 30)
    
    img = Image.new('RGB', (width, height))
    draw = ImageDraw.Draw(img)
    
    for y in range(height):
        ratio = y / height
        color_r = int(107 + (150 - 107) * ratio)
        color_g = int(127 + (180 - 127) * ratio)
        color_b = int(215 + (220 - 215) * ratio)
        draw.rectangle([(0, y), (width, y+1)], fill=(color_r, color_g, color_b))
    
    for _ in range(150):
        x = random.randint(0, width)
        y = random.randint(0, height)
        size = random.randint(2, 4)
        draw.ellipse([x, y, x+size, y+size], fill=(255, 255, 255))
    
    slot_coords = [target_x, target_y, target_x + piece_size, target_y + piece_size]
    draw.rectangle(slot_coords, fill=(30, 30, 40), outline=(255, 255, 255), width=3)
    
    shadow_coords = [target_x + 5, target_y + 5, target_x + piece_size - 5, target_y + piece_size - 5]
    draw.rectangle(shadow_coords, fill=(20, 20, 30))
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    background_base64 = base64.b64encode(img_byte_arr.getvalue()).decode()
    
    piece_img = Image.new('RGBA', (piece_size, piece_size), (0, 0, 0, 0))
    piece_draw = ImageDraw.Draw(piece_img)
    
    piece_coords = [0, 0, piece_size, piece_size]
    piece_draw.rectangle(piece_coords, fill=(107, 127, 215), outline=(255, 255, 255), width=3)
    
    piece_draw.line([(0, piece_size-1), (piece_size, piece_size-1)], fill=(80, 100, 180), width=2)
    piece_draw.line([(piece_size-1, 0), (piece_size-1, piece_size)], fill=(80, 100, 180), width=2)
    piece_draw.line([(0, 0), (piece_size, 0)], fill=(150, 170, 240), width=2)
    piece_draw.line([(0, 0), (0, piece_size)], fill=(150, 170, 240), width=2)
    
    piece_byte_arr = io.BytesIO()
    piece_img.save(piece_byte_arr, format='PNG')
    piece_base64 = base64.b64encode(piece_byte_arr.getvalue()).decode()
    
    return {
        'background': background_base64,
        'piece': piece_base64,
        'target_x': target_x,
        'target_y': target_y,
        'piece_size': piece_size,
        'tolerance': 30
    }

# Fungsi untuk kirim email OTP
def send_email_otp_flask(user_email, otp_code):
    """Kirim OTP menggunakan Flask-Mail"""
    try:
        msg = Message(
            subject='Kode Verifikasi OTP - 2FA System',
            recipients=[user_email],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        msg.html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: #f8f9fa; padding: 30px; border-radius: 10px;">
                    <h2 style="color: #667eea;">Kode Verifikasi OTP</h2>
                    <p>Seseorang baru saja mencoba login ke akun Anda.</p>
                    <p>Gunakan kode berikut untuk menyelesaikan proses login:</p>
                    <div style="background: white; padding: 20px; border-radius: 5px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #667eea; letter-spacing: 5px; font-size: 36px;">{otp_code}</h1>
                    </div>
                    <p style="color: #666;">Kode ini akan kadaluarsa dalam <strong>5 menit</strong>.</p>
                    <p style="color: #666;">Jika Anda tidak melakukan login, abaikan email ini.</p>
                    <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
                    <p style="font-size: 12px; color: #999;">Email otomatis dari 2FA System. Jangan balas email ini.</p>
                </div>
            </body>
        </html>
        """
        mail.send(msg)
        print(f"✅ Email berhasil dikirim ke {user_email}")
        return True
    except Exception as e:
        print(f"❌ Error Flask-Mail: {str(e)}")
        return False

def send_email_otp_smtp(user_email, otp_code):
    """Kirim OTP menggunakan smtplib langsung"""
    try:
        sender_email = "yannzzz13@gmail.com"
        password = "zhqy klci ywud pvnm"
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Kode Verifikasi OTP - 2FA System'
        msg['From'] = sender_email
        msg['To'] = user_email
        
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: #f8f9fa; padding: 30px; border-radius: 10px;">
                    <h2 style="color: #667eea;">Kode Verifikasi OTP</h2>
                    <p>Seseorang baru saja mencoba login ke akun Anda.</p>
                    <p>Gunakan kode berikut untuk menyelesaikan proses login:</p>
                    <div style="background: white; padding: 20px; border-radius: 5px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #667eea; letter-spacing: 5px; font-size: 36px;">{otp_code}</h1>
                    </div>
                    <p style="color: #666;">Kode ini akan kadaluarsa dalam <strong>5 menit</strong>.</p>
                    <p style="color: #666;">Jika Anda tidak melakukan login, abaikan email ini.</p>
                    <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
                    <p style="font-size: 12px; color: #999;">Email otomatis dari 2FA System. Jangan balas email ini.</p>
                </div>
            </body>
        </html>
        """
        
        text = f"Kode OTP Anda adalah: {otp_code}. Kode ini akan kadaluarsa dalam 5 menit."
        
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.send_message(msg)
        
        print(f"✅ Email berhasil dikirim ke {user_email} (via SMTP)")
        return True
    except Exception as e:
        print(f"❌ Error SMTP: {str(e)}")
        return False

def send_email_otp(user_email, otp_code):
    """Coba kirim email dengan Flask-Mail, jika gagal gunakan SMTP langsung"""
    print(f"Mencoba mengirim OTP ke {user_email}...")
    
    if send_email_otp_flask(user_email, otp_code):
        return True
    
    print("Flask-Mail gagal, mencoba SMTP langsung...")
    
    if send_email_otp_smtp(user_email, otp_code):
        return True
    
    print("❌ Semua metode pengiriman email gagal!")
    return False

# Route Index
@app.route('/')
def index():
    return redirect(url_for('login'))

# Route Registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        slider_position = request.form.get('slider_position', '0')
        
        captcha_data = session.get('captcha_data', {})
        target_x = captcha_data.get('target_x', 150)
        tolerance = captcha_data.get('tolerance', 30)
        
        try:
            slider_x = int(float(slider_position))
            distance = abs(slider_x - target_x)
            print(f"DEBUG REGISTER - Slider: {slider_x}px, Target: {target_x}px, Distance: {distance}px")
            
            if distance > tolerance:
                flash(f'Captcha gagal! Posisi Anda: {slider_x}px, harus di sekitar {target_x}px (±{tolerance}px)', 'danger')
                return redirect(url_for('register'))
        except Exception as e:
            print(f"Error validating captcha: {e}")
            flash('Captcha tidak valid!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username sudah digunakan!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email sudah terdaftar!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        otp_secret = pyotp.random_base32()
        
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            otp_secret=otp_secret,
            email_otp_enabled=False
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    
    captcha_data = generate_slider_captcha()
    session['captcha_data'] = {
        'target_x': captcha_data['target_x'],
        'target_y': captcha_data['target_y'],
        'tolerance': captcha_data['tolerance']
    }
    
    return render_template('register.html', 
                         captcha_background=captcha_data['background'],
                         captcha_piece=captcha_data['piece'],
                         target_y=captcha_data['target_y'],
                         piece_size=captcha_data['piece_size'])

# Route Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        slider_position = request.form.get('slider_position', '0')
        
        captcha_data = session.get('captcha_data', {})
        target_x = captcha_data.get('target_x', 150)
        tolerance = captcha_data.get('tolerance', 30)
        
        try:
            slider_x = int(float(slider_position))
            distance = abs(slider_x - target_x)
            print(f"DEBUG LOGIN - Slider: {slider_x}px, Target: {target_x}px, Distance: {distance}px")
            
            if distance > tolerance:
                flash(f'Captcha gagal! Posisi Anda: {slider_x}px, harus di sekitar {target_x}px (±{tolerance}px)', 'danger')
                
                log = LoginLog(
                    username=username,
                    status='failed_captcha',
                    ip_address=request.remote_addr
                )
                db.session.add(log)
                db.session.commit()
                
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Error validating captcha: {e}")
            flash('Captcha tidak valid!', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['temp_user_id'] = user.id
            session['temp_username'] = username
            
            log = LoginLog(
                username=username,
                status='pending_otp',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            # REDIRECT KE HALAMAN PILIHAN VERIFIKASI
            return redirect(url_for('choose_verification'))
        else:
            log = LoginLog(
                username=username,
                status='failed',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Username atau password salah!', 'danger')
    
    captcha_data = generate_slider_captcha()
    session['captcha_data'] = {
        'target_x': captcha_data['target_x'],
        'target_y': captcha_data['target_y'],
        'tolerance': captcha_data['tolerance']
    }
    
    return render_template('login.html', 
                         captcha_background=captcha_data['background'],
                         captcha_piece=captcha_data['piece'],
                         target_y=captcha_data['target_y'],
                         piece_size=captcha_data['piece_size'])

# ========== ROUTE BARU: PILIHAN VERIFIKASI ==========
@app.route('/choose-verification')
def choose_verification():
    """Halaman untuk memilih metode verifikasi (QR/Authenticator atau Email)"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['temp_user_id'])
    
    # Generate QR Code untuk Authenticator
    totp = pyotp.TOTP(user.otp_secret)
    uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='2FA System'
    )
    
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    
    return render_template('choose_verification.html',
                         qr_code=qr_code,
                         secret=user.otp_secret,
                         user_email=user.email)

# Route untuk kirim OTP via Email
@app.route('/send-email-otp', methods=['POST'])
def send_email_otp_route():
    """Kirim OTP ke email user"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['temp_user_id'])
    
    # Generate OTP 6 digit
    otp_code = ''.join(random.choices(string.digits, k=6))
    
    print(f"🔐 Generated OTP: {otp_code} untuk user: {user.email}")
    
    # Simpan OTP ke database dengan expire 5 menit
    email_otp = EmailOTP(
        user_id=user.id,
        otp_code=otp_code,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(email_otp)
    db.session.commit()
    
    # Kirim email
    if send_email_otp(user.email, otp_code):
        flash(f'Kode OTP telah dikirim ke {user.email}', 'success')
        print(f"✅ OTP berhasil dikirim dan disimpan ke database")
    else:
        flash(f'Gagal mengirim email. Kode OTP untuk testing: {otp_code}', 'warning')
        print(f"⚠️ DEBUG MODE - OTP Code: {otp_code}")
    
    return redirect(url_for('choose_verification'))

# Route untuk verifikasi OTP Authenticator
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Verifikasi OTP dari Authenticator App"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    otp_code = request.form.get('otp_code')
    user = User.query.get(session['temp_user_id'])
    
    totp = pyotp.TOTP(user.otp_secret)
    
    if totp.verify(otp_code, valid_window=1):
        # Login berhasil
        session.pop('temp_user_id', None)
        session.pop('temp_username', None)
        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = True
        
        log = LoginLog(
            username=user.username,
            status='success',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Login berhasil dengan Authenticator!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Kode OTP Authenticator salah!', 'danger')
        return redirect(url_for('choose_verification'))

# Route untuk verifikasi OTP Email
@app.route('/verify-email-otp', methods=['POST'])
def verify_email_otp():
    """Verifikasi OTP dari Email"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    otp_input = request.form.get('otp_code')
    user = User.query.get(session['temp_user_id'])
    
    # Cari OTP yang valid
    email_otp = EmailOTP.query.filter_by(
        user_id=user.id,
        otp_code=otp_input,
        is_used=False
    ).filter(EmailOTP.expires_at > datetime.utcnow()).first()
    
    if email_otp:
        # OTP valid
        email_otp.is_used = True
        db.session.commit()
        
        # Login berhasil
        session.pop('temp_user_id', None)
        session.pop('temp_username', None)
        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = True
        
        log = LoginLog(
            username=user.username,
            status='success',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Login berhasil dengan Email OTP!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Kode OTP Email salah atau sudah kadaluarsa!', 'danger')
        return redirect(url_for('choose_verification'))

# Route Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    logs = LoginLog.query.filter_by(username=user.username)\
                        .order_by(LoginLog.timestamp.desc())\
                        .limit(10).all()
    
    return render_template('dashboard.html', user=user, logs=logs)

# Route untuk ganti metode 2FA (opsional, untuk dashboard)
@app.route('/toggle-2fa-method', methods=['POST'])
def toggle_2fa_method():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    user.email_otp_enabled = not user.email_otp_enabled
    db.session.commit()
    
    method = "Email OTP" if user.email_otp_enabled else "Authenticator App"
    flash(f'Metode 2FA berhasil diganti ke: {method}', 'success')
    
    return redirect(url_for('dashboard'))

# Route untuk test email
@app.route('/test-email')
def test_email():
    """Route untuk test pengiriman email"""
    test_email_addr = "yannzzz13@gmail.com"
    test_otp = "123456"
    
    if send_email_otp(test_email_addr, test_otp):
        return "✅ Email berhasil dikirim! Cek inbox Anda."
    else:
        return "❌ Email gagal dikirim. Cek console untuk error details."

# Route Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)