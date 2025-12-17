from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from itsdangerous import URLSafeTimedSerializer
import secrets, random, string
from datetime import datetime

# ------------------ APP CONFIG ------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = secrets.token_hex(16)

db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.secret_key)

# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    key = db.Column(db.String(200), nullable=False)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------ DB INIT ------------------
with app.app_context():
    db.create_all()

# ------------------ DASHBOARD ------------------
@app.route('/')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    fernet = Fernet(user.key.encode())

    passwords = Password.query.filter_by(user_id=user.id).all()

    decrypted = []
    for p in passwords:
        decrypted.append({
            'id': p.id,
            'website': p.website,
            'password': fernet.decrypt(p.password.encode()).decode(),
            'category': p.category or '—',
            'last_updated': p.last_updated.strftime('%Y-%m-%d %H:%M')
        })

    return render_template(
        'dashboard.html',
        passwords=decrypted,
        username=user.username
    )

# ------------------ SIGNUP ------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        pwd = request.form['password']

        if User.query.filter_by(email=email).first():
            flash("Email already registered")
            return redirect('/signup')

        user = User(
            email=email,
            username=username,
            password=generate_password_hash(pwd),
            key=Fernet.generate_key().decode()
        )

        db.session.add(user)
        db.session.commit()

        flash("Signup successful. Login now.")
        return redirect('/login')

    return render_template('signup.html')

# ------------------ LOGIN ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pwd = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, pwd):
            session['user_id'] = user.id
            return redirect('/')

        flash("Invalid credentials")
        return redirect('/login')

    return render_template('login.html')

# ------------------ LOGOUT ------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ------------------ ADD PASSWORD ------------------
@app.route('/add', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        website = request.form['website']
        pwd = request.form['password']
        category = request.form.get('category')

        user = User.query.get(session['user_id'])
        fernet = Fernet(user.key.encode())

        encrypted = fernet.encrypt(pwd.encode()).decode()

        db.session.add(
            Password(
                website=website,
                password=encrypted,
                category=category,
                user_id=user.id
            )
        )
        db.session.commit()
        return redirect('/')

    return render_template('add_password.html')

# ------------------ DELETE PASSWORD (GET, SIMPLE) ------------------
@app.route('/delete/<int:id>')
def delete_password(id):
    if 'user_id' not in session:
        return redirect('/login')

    pwd = Password.query.get_or_404(id)
    if pwd.user_id != session['user_id']:
        flash("Unauthorized")
        return redirect('/')

    db.session.delete(pwd)
    db.session.commit()
    return redirect('/')

# ------------------ PASSWORD GENERATOR ------------------
@app.route('/generate_password')
def generate_password():
    length = int(request.args.get('length', 16))
    chars = string.ascii_letters + string.digits + string.punctuation
    pwd = ''.join(random.choice(chars) for _ in range(length))
    return jsonify({'password': pwd})

# ------------------ FORGOT PASSWORD ------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email not found")
            return redirect('/forgot_password')

        token = s.dumps(email, salt='reset-password')
        flash(f"DEV RESET LINK: /reset_password/{token}")
        return redirect('/login')

    return render_template('forgot_password.html')

# ------------------ RESET PASSWORD ------------------
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='reset-password', max_age=3600)
    except:
        flash("Invalid or expired token")
        return redirect('/login')

    if request.method == 'POST':
        pwd = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(pwd)
        db.session.commit()
        flash("Password updated")
        return redirect('/login')

    return render_template('reset_password.html')

# ------------------ RUN ------------------
if __name__ == '__main__':
    app.run(debug=True)
