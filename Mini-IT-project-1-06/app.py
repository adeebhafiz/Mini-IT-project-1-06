from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from datetime import datetime

# Initialize extensions
socketio = SocketIO()
db = SQLAlchemy()
login_manager = LoginManager()

# Image upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Integer, default=0)
    reports = db.relationship('Report', back_populates='user', cascade='all, delete-orphan')
    suggestions = db.relationship('Suggestion', back_populates='user', cascade='all, delete-orphan')
    comments = db.relationship('Comment', back_populates='user', cascade='all, delete-orphan')
    report_comments = db.relationship('ReportComment', back_populates='user', cascade='all, delete-orphan')

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    faculty = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(50), nullable=False)
    problem = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='reports')
    comments = db.relationship('ReportComment', back_populates='report', cascade='all, delete-orphan')

class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    suggestion = db.Column(db.String(300), nullable=False)
    faculty = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Pending')
    votes = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='suggestions')
    comments = db.relationship('Comment', back_populates='suggestion', cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    suggestion_id = db.Column(db.Integer, db.ForeignKey('suggestion.id'), nullable=False)
    user = db.relationship('User', back_populates='comments')
    suggestion = db.relationship('Suggestion', back_populates='comments')

class ReportComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    user = db.relationship('User', back_populates='report_comments')
    report = db.relationship('Report', back_populates='comments')

# App factory
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    socketio.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role=1).first():
            admin_user = User(
                username="admin",
                email="admin@example.com",
                password=generate_password_hash("admin123"),
                role=1
            )
            db.session.add(admin_user)
            db.session.commit()

    # Routes
    @app.route('/')
    def homepage():
        return render_template('homepage.html')

    @app.route('/main')
    def index():
        return render_template('index.html')

    @app.route('/about')
    def about():
        return render_template('about.html')

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
        image = request.files.get('image')

        image_filename = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            image_filename = filename

        new_report = Report(
            faculty=faculty,
            level=level,
            problem=problem,
            image_filename=image_filename,
            user=current_user
        )
        db.session.add(new_report)
        db.session.commit()
        return redirect(url_for('review'))

    @app.route('/review')
    def review():
        reports = Report.query.order_by(Report.date_created.desc()).all()
        return render_template('review.html', reports=reports)

    # Comments on reports (chit-chat)
    @app.route('/report/<int:report_id>/comments')
    @login_required
    def get_report_comments(report_id):
        report = Report.query.get_or_404(report_id)
        comments = [
            {
                'username': c.user.username,
                'content': c.content,
                'timestamp': c.timestamp.strftime('%Y-%m-%d %H:%M')
            } for c in report.comments
        ]
        return jsonify(comments)

    @app.route('/report/<int:report_id>/comment', methods=['POST'])
    @login_required
    def post_report_comment(report_id):
        if current_user.role != 1:
            return jsonify({'error': 'Only admins can comment on reports.'}), 403

        content = request.form.get('content', '').strip()
        if not content:
            return jsonify({'error': 'Comment cannot be empty.'}), 400

        report = Report.query.get_or_404(report_id)
        new_comment = ReportComment(content=content, user=current_user, report=report)
        db.session.add(new_comment)
        db.session.commit()
        return jsonify({'success': True})

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

            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login'))

        return render_template('signup_student.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password, password):
                flash('Invalid credentials.', 'danger')
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
    @login_required
    def view():
        return render_template('view.html')

    @app.route('/admin')
    @login_required
    def admin():
        if current_user.role != 1:
            flash('Access denied.', 'danger')
            return redirect(url_for('homepage'))

        selected_faculty = request.args.get('faculty')
        faculties = db.session.query(Report.faculty).distinct().order_by(Report.faculty).all()
        faculties = [f[0] for f in faculties]

        if not selected_faculty and faculties:
            selected_faculty = faculties[0]

        reports = Report.query.filter_by(faculty=selected_faculty).order_by(Report.date_created.desc()).all() if selected_faculty else []
        total_reports = len(reports)

        return render_template('admin1.html', selected_faculty=selected_faculty, faculties=faculties, reports=reports, total_reports=total_reports)

    @app.route('/submit_suggestion', methods=['POST'])
    @login_required
    def submit_suggestion():
        suggestion = request.form.get('suggestion')
        faculty = request.form.get('faculty')
        reason = request.form.get('reason')

        new_suggestion = Suggestion(suggestion=suggestion, faculty=faculty, reason=reason, user=current_user)
        db.session.add(new_suggestion)
        db.session.commit()
        return redirect(url_for('suggestion_confirmation'))

    @app.route('/suggestion_confirmation')
    @login_required
    def suggestion_confirmation():
        return render_template('suggestion_confirmation.html')

    @app.route('/suggestions')
    @login_required
    def suggestions():
        posts = Suggestion.query.order_by(Suggestion.timestamp.desc()).all()
        return render_template('reviewsuggest.html', posts=posts)

    @app.route('/upvote/<int:suggestion_id>', methods=['POST'])
    @login_required
    def upvote(suggestion_id):
        suggestion = Suggestion.query.get_or_404(suggestion_id)
        suggestion.votes += 1
        db.session.commit()
        return jsonify(success=True, votes=suggestion.votes)

    @app.route('/get_comments/<int:suggestion_id>')
    @login_required
    def get_comments(suggestion_id):
        suggestion = Suggestion.query.get_or_404(suggestion_id)
        comments = [
            {
                'username': c.user.username,
                'content': c.content,
                'timestamp': c.timestamp.strftime('%Y-%m-%d %H:%M')
            } for c in suggestion.comments
        ]
        return jsonify(comments)

    @app.route('/comment/<int:suggestion_id>', methods=['POST'])
    @login_required
    def comment(suggestion_id):
        content = request.form.get('content')
        if not content:
            flash('Comment cannot be empty.', 'danger')
            return redirect(url_for('suggestions'))

        suggestion = Suggestion.query.get_or_404(suggestion_id)
        new_comment = Comment(content=content, user=current_user, suggestion=suggestion)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('suggestions'))

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)
