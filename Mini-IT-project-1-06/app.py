from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash

socketio = SocketIO()
db = SQLAlchemy()


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    faculty = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(50), nullable=False)
    problem = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    socketio.init_app(app)
    db.init_app(app)

    
    with app.app_context():
        db.create_all()

    
    @app.route('/')
    def homepage():
        return render_template('homepage.html')

    @app.route('/main')
    def main():
        return render_template('index.html')

    @app.route('/form')
    def form():
        return render_template('form.html')

    @app.route('/submit', methods=['POST'])
    def submit():
        faculty = request.form.get('faculty')
        level = request.form.get('level')
        problem = request.form.get('problem')

        new_report = Report(faculty=faculty, level=level, problem=problem)
        db.session.add(new_report)
        db.session.commit()

        return redirect(url_for('review'))

    @app.route('/review')
    def review():
        reports = Report.query.order_by(Report.date_created.desc()).all()
        return render_template('review.html', reports=reports)

   
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return redirect(url_for('signup'))

            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('signup'))

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Signup successful! You can now log in.', 'success')
            return redirect(url_for('homepage'))

        return render_template('signup_student.html')

    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password, password):
                flash('Invalid username or password.', 'danger')
                return redirect(url_for('login'))

            flash('Login successful!', 'success')
            return redirect(url_for('view'))

        return render_template('login.html')

    @app.route('/about')
    def about():
        return render_template('about.html')

    @app.route('/view')
    def view():
        return render_template('view.html')

    @app.route('/suggestions')
    def suggestion():
        return render_template('suggestions.html')

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)