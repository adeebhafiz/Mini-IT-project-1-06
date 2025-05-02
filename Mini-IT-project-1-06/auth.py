from flask import Blueprint, render_template, request, redirect, url_for, session
import hashlib

auth = Blueprint('auth', __name__)

# Simple in-memory "database"
users_db = {}

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return "Passwords do not match.", 400

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Store user in the "database"
        users_db[email] = hashed_password

        return redirect(url_for('auth.login'))

    return render_template('signup_student.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Check if the user exists and password is correct
        if email in users_db and users_db[email] == hashed_password:
            session['user'] = email
            return redirect(url_for('homepage.home'))
        else:
            return "Invalid credentials. Please try again.", 400

    return render_template('login.html')
