from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO
import sqlite3
import hashlib
import os

socketio = SocketIO()

# In-memory report storage
reports = []

# Initialize the database
def init_db():
    if not os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'student'
            )
        ''')
        conn.commit()
        conn.close()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'

    socketio.init_app(app)
    init_db()

    # Homepage
    @app.route('/')
    def homepage():
        return render_template('homepage.html')

    # Main report interface
    @app.route('/main')
    def main():
        return render_template('index.html')

    # Complaint form page
    @app.route('/form')
    def form():
        return render_template('form.html')

    # Submit report
    @app.route('/submit', methods=['POST'])
    def submit():
        faculty = request.form.get('faculty')
        level = request.form.get('level')
        problem = request.form.get('problem')

        reports.append({
            'faculty': faculty,
            'level': level,
            'problem': problem
        })

        return redirect(url_for('review'))

    # View submitted reports
    @app.route('/review')
    def review():
        return render_template('review.html', reports=reports)

    # About page
    @app.route('/about')
    def about():
        return render_template('about.html')

    # View page
    @app.route('/view')
    def view():
        return render_template('view.html')

    # Suggestions page
    @app.route('/suggestions')
    def suggestion():
        return render_template('suggestions.html')

    # Signup
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role', 'student')

            if password != confirm_password:
                return "Passwords do not match!", 400

            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            try:
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)',
                    (email, hashed_password, full_name, role)
                )
                conn.commit()
                conn.close()
            except sqlite3.IntegrityError:
                return "Email already exists", 400

            return redirect(url_for('login'))

        return render_template('signup_student.html')

    # Login
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM users WHERE email = ? AND password = ?',
                (email, hashed_password)
            )
            user = cursor.fetchone()
            conn.close()

            if user:
                session['user_id'] = user[0]
                session['full_name'] = user[3]
                session['role'] = user[4]
                return redirect(url_for('main'))
            else:
                return "Invalid credentials", 401

        return render_template('login.html')

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)
