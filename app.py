from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Encryption Key (Always keep secure in production)
fernet_key = b'2xZHlbwM8MAr_YiyM9UsH0AhkckDPFwka6FWYY9ZjKw='
cipher_suite = Fernet(fernet_key)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.Text, nullable=True)

class SavedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        profile_pic = request.files.get('profile_pic')

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            return render_template('sign-up.html', error="Username or email already exists.")

        encoded_image = None
        if profile_pic:
            encoded_image = base64.b64encode(profile_pic.read()).decode('utf-8')

        new_user = User(username=username, email=email, password=password, profile_pic=encoded_image)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('sign-up.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            return redirect('/dashboard')
        else:
            return render_template('sign-in.html', error="Invalid credentials")
    return render_template('sign-in.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/add-password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect('/login')
    if request.method == 'POST':
        name = request.form['name']
        plain_password = request.form['password']
        encrypted_password = cipher_suite.encrypt(plain_password.encode()).decode()
        new_entry = SavedPassword(user_id=session['user_id'], name=name, password=encrypted_password)
        db.session.add(new_entry)
        db.session.commit()
        return redirect('/dashboard')
    return render_template('add-password.html')

@app.route('/saved-passwords')
def saved_passwords():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    saved_passwords = SavedPassword.query.filter_by(user_id=user.id).all()

    decrypted_passwords = []
    for item in saved_passwords:
        try:
            decrypted = cipher_suite.decrypt(item.password.encode()).decode()
        except Exception:
            decrypted = "[Decryption Failed]"
        decrypted_passwords.append({
            'name': item.name,
            'password': decrypted
        })

    return render_template('saved-passwords.html', user=user, passwords=decrypted_passwords)

@app.route('/generate-password')
def generate_password():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('generate-password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
