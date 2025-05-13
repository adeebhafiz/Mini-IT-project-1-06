from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

socketio = SocketIO()
db = SQLAlchemy()
login_manager = LoginManager()

# ---------------- Models ----------------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    faculty = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(50), nullable=False)
    problem = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='reports')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Integer, default=0)  # 0 = student, 1 = admin

    reports = db.relationship('Report', back_populates='user', cascade='all, delete-orphan')

# ---------------- App Factory ----------------
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    socketio.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin_user = User(username="admin", email="admin@example.com", password=generate_password_hash("admin123"), role=1)
            db.session.add(admin_user)
            db.session.commit()

    # ---------------- Routes ----------------
    @app.route('/')
    def homepage():
        return render_template('homepage.html')

    @app.route('/form')
    @login_required
    def form():
        return render_template('form.html')

    @app.route('/submit', methods=['POST'])
    @login_required
    def submit():
        faculty = request.form.get('faculty')
        level = request.form.get('level')
        problem = request.form.get('problem')

        new_report = Report(faculty=faculty, level=level, problem=problem, user=current_user)
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

            return redirect(url_for('login'))

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

            login_user(user)
            return redirect(url_for('admin' if user.role == 1 else 'view'))

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out successfully.', 'info')
        return redirect(url_for('homepage'))

    @app.route('/view')
    def view():
        return render_template('view.html')

    @app.route('/admin')
    @login_required
    def admin():
        if current_user.role != 1:
            flash('Access denied.', 'danger')
            return redirect(url_for('homepage'))

        # Get the selected faculty from the query parameter or set to None for all faculties
        selected_faculty = request.args.get('faculty')

        # Fetch all unique faculties from the Report model
        faculties = db.session.query(Report.faculty).distinct().order_by(Report.faculty).all()
        faculties = [f[0] for f in faculties]

        # Set default faculty to the first one if none is selected
        if not selected_faculty and faculties:
            selected_faculty = faculties[0]

        # Query the reports filtered by the selected faculty
        reports = Report.query.filter_by(faculty=selected_faculty).order_by(Report.date_created.desc()).all() if selected_faculty else []
        total_reports = len(reports)

        return render_template(
            'admin1.html',
            selected_faculty=selected_faculty,
            faculties=faculties,
            reports=reports,
            total_reports=total_reports
        )

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)
