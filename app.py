import os
from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import json
from datetime import datetime
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Cho session
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Tạo thư mục uploads nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Khởi tạo database
def init_db():
    conn = sqlite3.connect('file_transfer.db')
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    # Contacts table
    c.execute('''CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    # File transfers table
    c.execute('''CREATE TABLE IF NOT EXISTS file_transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        signature TEXT NOT NULL,
        sender_id INTEGER,
        receiver_id INTEGER,
        hash_algo TEXT NOT NULL,
        sign_algo TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES contacts (id))''')
    conn.commit()
    conn.close()

init_db()

# Tạo cặp khóa RSA
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Lưu private key
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Lưu public key
    with open('public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key, public_key

# Ký số file
def sign_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Tạo hash SHA-256
    hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_obj.update(data)
    file_hash = hash_obj.finalize()
    
    # Ký hash
    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8'), base64.b64encode(file_hash).decode('utf-8')

# Xác thực chữ ký
def verify_signature(file_path, signature, public_key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Tạo hash SHA-256
    hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_obj.update(data)
    file_hash = hash_obj.finalize()
    
    try:
        public_key.verify(
            base64.b64decode(signature),
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, base64.b64encode(file_hash).decode('utf-8')
    except Exception:
        return False, None

# User auth helpers
def get_user_by_username(username):
    conn = sqlite3.connect('file_transfer.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = sqlite3.connect('file_transfer.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    return user

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required!', 'danger')
            return redirect(url_for('register'))
        if get_user_by_username(username):
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        password_hash = generate_password_hash(password)
        conn = sqlite3.connect('file_transfer.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/contacts')
def contacts():
    conn = sqlite3.connect('file_transfer.db')
    c = conn.cursor()
    c.execute('SELECT * FROM contacts ORDER BY created_at DESC')
    contacts = c.fetchall()
    conn.close()
    return render_template('contacts.html', contacts=contacts)

@app.route('/add_contact', methods=['POST'])
def add_contact():
    name = request.form.get('name')
    public_key = request.form.get('public_key')
    
    if not name or not public_key:
        return jsonify({'error': 'Name and public key are required'}), 400
    
    conn = sqlite3.connect('file_transfer.db')
    c = conn.cursor()
    c.execute('INSERT INTO contacts (name, public_key) VALUES (?, ?)',
              (name, public_key))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Contact added successfully'})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'You must be logged in to upload files.'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    receiver_id = request.form.get('receiver_id')
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if not receiver_id:
        return jsonify({'error': 'No receiver selected'}), 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        private_key, public_key = generate_key_pair()
        signature, file_hash = sign_file(file_path, private_key)
        conn = sqlite3.connect('file_transfer.db')
        c = conn.cursor()
        c.execute('''INSERT INTO file_transfers 
                    (filename, signature, sender_id, receiver_id, hash_algo, sign_algo)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                 (filename, signature, session['user_id'], receiver_id, 'SHA-256', 'RSA'))
        transfer_id = c.lastrowid
        conn.commit()
        conn.close()
        with open('public_key.pem', 'rb') as f:
            public_key_b64 = base64.b64encode(f.read()).decode('utf-8')
        return jsonify({
            'message': 'File uploaded and signed successfully',
            'filename': filename,
            'signature': signature,
            'file_hash': file_hash,
            'public_key': public_key_b64,
            'transfer_id': transfer_id,
            'timestamp': datetime.now().isoformat()
        })

@app.route('/verify', methods=['POST'])
def verify_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    signature = request.form.get('signature')
    public_key = request.form.get('public_key')
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not signature:
        return jsonify({'error': 'No signature provided'}), 400
    
    if not public_key:
        return jsonify({'error': 'No public key provided'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Load public key
        try:
            public_key_bytes = base64.b64decode(public_key)
            public_key = serialization.load_pem_public_key(
                public_key_bytes,
                backend=default_backend()
            )
        except Exception as e:
            return jsonify({'error': f'Invalid public key: {str(e)}'}), 400
        
        # Xác thực chữ ký
        is_valid, file_hash = verify_signature(file_path, signature, public_key)
        
        return jsonify({
            'message': 'Signature verification completed',
            'is_valid': is_valid,
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat()
        })

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(
        os.path.join(app.config['UPLOAD_FOLDER'], filename),
        as_attachment=True
    )

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('file_transfer.db')
    c = conn.cursor()
    c.execute('''
        SELECT ft.*, c.name as receiver_name, u.username as sender_name 
        FROM file_transfers ft 
        LEFT JOIN contacts c ON ft.receiver_id = c.id 
        LEFT JOIN users u ON ft.sender_id = u.id
        ORDER BY ft.created_at DESC
    ''')
    transfers = c.fetchall()
    conn.close()
    return render_template('history.html', transfers=transfers)

if __name__ == '__main__':
    app.run(debug=True) 