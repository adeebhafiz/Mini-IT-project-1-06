from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import os
import uuid
from sqlalchemy import func # <-- ADDED THIS IMPORT

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize extensions
db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()

# Utilities
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def unique_filename(filename):
    ext = filename.rsplit('.', 1)[1]
    return f"{uuid.uuid4().hex}.{ext}"

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Integer, default=0)  # 0 = user, 1 = admin

    reports = db.relationship('Report', back_populates='user', cascade='all, delete-orphan')
    suggestions = db.relationship('Suggestion', back_populates='user', cascade='all, delete-orphan')
    comments = db.relationship('Comment', back_populates='user', cascade='all, delete-orphan')
    report_comments = db.relationship('ReportComment', back_populates='user', cascade='all, delete-orphan')
    votes = db.relationship('Vote', back_populates='user', cascade='all, delete-orphan')

class StatusUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text)
    assigned_to = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')
    report = db.relationship('Report', backref='status_updates')

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    faculty = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(50), nullable=False)
    problem = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    status = db.Column(db.String(50), default='in progress')
    assigned_to = db.Column(db.String(100))

    user = db.relationship('User', back_populates='reports')
    comments = db.relationship('ReportComment', back_populates='report', cascade='all, delete-orphan')

class ReportComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)

    user = db.relationship('User', back_populates='report_comments')
    report = db.relationship('Report', back_populates='comments')

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
    vote_records = db.relationship('Vote', back_populates='suggestion', cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    suggestion_id = db.Column(db.Integer, db.ForeignKey('suggestion.id'), nullable=False)

    user = db.relationship('User', back_populates='comments')
    suggestion = db.relationship('Suggestion', back_populates='comments')

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    suggestion_id = db.Column(db.Integer, db.ForeignKey('suggestion.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='votes')
    suggestion = db.relationship('Suggestion', back_populates='vote_records')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'suggestion_id', name='unique_user_suggestion_vote'),
    )

# App Factory
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB max file size

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    db.init_app(app)
    socketio.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        # Create default admin if none exists
        if not User.query.filter_by(role=1).first():
            admin_user = User(
                username="admin",
                email="admin@example.com",
                password=generate_password_hash("admin123"),
                role=1
            )
            db.session.add(admin_user)
            db.session.commit()

    register_routes(app)
    register_socket_events(socketio)

    return app


# Socket.IO Events
def register_socket_events(socketio):

    @socketio.on('connect')
    def handle_connect():
        emit('message', {'msg': 'Connected to server'})

    @socketio.on('new_report')
    def handle_new_report(data):
        # Broadcast new report event to all clients
        emit('new_report', data, broadcast=True)


# Routes
def register_routes(app):

    @app.route('/')
    def homepage():
        return render_template('homepage.html')

    @app.route('/suggest')
    @login_required
    def suggest():
        return render_template('suggestionform.html')

    @app.route('/main')
    @login_required
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
            filename = unique_filename(secure_filename(image.filename))
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            image_filename = filename

        new_report = Report(faculty=faculty, level=level, problem=problem,
                             image_filename=image_filename, user=current_user)
        try:
            db.session.add(new_report)
            db.session.commit()
            # Emit socket event to notify clients about new report
            socketio.emit('new_report', {
                'id': new_report.id,
                'faculty': new_report.faculty,
                'level': new_report.level,
                'problem': new_report.problem,
                'image_filename': new_report.image_filename,
                'date_created': new_report.date_created.strftime('%Y-%m-%d %H:%M'),
                'user': current_user.username
            }, broadcast=True)
        except Exception as e:
            db.session.rollback()
            flash('Error submitting report.', 'danger')
            return redirect(url_for('form'))

        # Redirect to review page after successful submission
        return redirect(url_for('review'))

    @app.route('/review')
    @login_required
    def review():
        reports = Report.query.order_by(Report.date_created.desc()).all()
        return render_template('review.html', reports=reports)

    @app.route('/report/<int:report_id>/user_messages')
    @login_required
    def get_user_messages(report_id):
        report = Report.query.get_or_404(report_id)
        comments = [{
            'username': c.user.username,
            'message': c.content,
            'timestamp': c.timestamp.strftime('%Y-%m-%d %H:%M')
        } for c in report.comments]
        return jsonify(comments)

    @app.route('/report/<int:report_id>/user_message', methods=['POST'])
    @login_required
    def post_user_message(report_id):
        content = request.form.get('user_message', '').strip()
        if not content:
            return jsonify({'error': 'Message cannot be empty'}), 400

        report = Report.query.get_or_404(report_id)
        new_comment = ReportComment(content=content, user=current_user, report=report)
        db.session.add(new_comment)
        db.session.commit()

        return jsonify({
            'username': current_user.username,
            'message': content,
            'timestamp': new_comment.timestamp.strftime('%Y-%m-%d %H:%M')
        })

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

            # Redirect based on role
            if user.role == 1:
                return render_template('viewadmin.html')  # Show viewadmin.html directly
            else:
                return redirect(url_for('view'))  # Or another route for non-admins

        return render_template('login.html')


    @app.route('/logout', methods=['POST'])
    @login_required
    def logout():
        logout_user()
        flash('Logged out successfully.', 'info')
        return redirect(url_for('homepage'))  # make sure 'homepage' route exists


    @app.route('/view')
    @login_required
    def view():
        return render_template('view.html')
    
    @app.route('/viewadmin')
    @login_required
    def viewadmin():
        return render_template('viewadmin.html')
    
    @app.route('/suggest_admin')
    @login_required
    def suggest_admin():
        # Render the Suggest Admin page
        return render_template('map.html')
    
    @app.route('/admin_suggest')
    @login_required
    def admin_suggest():
        if current_user.role != 1:
            return redirect(url_for('view'))
        
        suggestions = Suggestion.query.order_by(Suggestion.timestamp.desc()).all()
        return render_template('admin_suggestion.html', suggestions=suggestions)


    @app.route('/report_admin')
    @login_required
    def report_admin():
        if current_user.role != 1:
            return redirect(url_for('view'))
        
        faculties = Report.query.with_entities(Report.faculty).distinct().all()
        faculties = [f[0] for f in faculties]

        selected_faculty = request.args.get('faculty')

        query = Report.query
        if selected_faculty:
            query = query.filter_by(faculty=selected_faculty)

        # Get all reports
        reports = query.order_by(Report.date_created.desc()).all()
        return render_template('admin1.html', 
                                 reports=reports,
                                 faculties=faculties,
                                 selected_faculty=selected_faculty)    
    
    @app.route('/return')
    def home():
        return render_template('homepage.html')
        
    @app.route('/admin')
    @login_required
    def admin_dashboard():
        if current_user.role != 1:
            return redirect(url_for('view'))
        
        faculties = Report.query.with_entities(Report.faculty).distinct().all()
        faculties = [f[0] for f in faculties]

        selected_faculty = request.args.get('faculty')

        query = Report.query
        if selected_faculty:
            query = query.filter_by(faculty=selected_faculty)

        # Get all reports
        reports = Report.query.order_by(Report.date_created.desc()).all()

        return render_template('admin1.html',reports=reports)


    @app.route('/submit_suggestion', methods=['POST'])
    @login_required
    def submit_suggestion():
        try:
            data = request.get_json()
            suggestion_text = data.get('suggestion')
            faculty = data.get('faculty')
            reason = data.get('reason')

            if not suggestion_text or not faculty or not reason:
                return jsonify({'success': False, 'error': 'All fields are required'}), 400

            new_suggestion = Suggestion(
                suggestion=suggestion_text,
                faculty=faculty,
                reason=reason,
                user_id=current_user.id
            )
            db.session.add(new_suggestion)
            db.session.commit()

            return jsonify({'success': True}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': f'Error submitting suggestion: {str(e)}'}), 500
        
    @app.route('/submit_comment/<int:post_id>', methods=['POST'])
    @login_required
    def submit_comment(post_id):
        try:
            data = request.get_json()
            content = data.get('content', '').strip()

            if not content:
                return jsonify({'error': 'Empty comment'}), 400

            comment = Comment(
                suggestion_id=post_id,
                user_id=current_user.id,
                content=content,
                timestamp=datetime.utcnow()
            )

            db.session.add(comment)
            db.session.commit()

            return jsonify({
                'success': True,
                'id': comment.id, # Return the comment ID for the HTML
                'username': current_user.username,
                'content': content,
                'timestamp': comment.timestamp.strftime('%Y-%m-%d %H:%M')
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Error submitting comment: {str(e)}'}), 500

    @app.route('/delete_comment/<int:comment_id>', methods=['DELETE'])
    @login_required
    def delete_comment(comment_id):
        # Ensure only admins can delete comments
        if current_user.role != 1:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        comment = Comment.query.get(comment_id)
        if not comment:
            return jsonify({'success': False, 'error': 'Comment not found'}), 404

        try:
            db.session.delete(comment)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Comment deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500


    @app.route('/get_comments/<int:post_id>')
    @login_required
    def get_comments(post_id):
        comments = Comment.query.filter_by(suggestion_id=post_id).order_by(Comment.timestamp.desc()).all()
        return jsonify([
            {
                'id': c.id, # Include comment ID
                'username': c.user.username,
                'content': c.content,
                'timestamp': c.timestamp.strftime('%Y-%m-%d %H:%M')
            } for c in comments
        ])


    @app.route('/suggestions')
    @login_required
    def suggestions():
        posts = Suggestion.query.order_by(Suggestion.timestamp.desc()).all()
        return render_template('suggestionreview.html', posts=posts)

    @app.route('/upvote/<int:suggestion_id>', methods=['POST'])
    @login_required
    def upvote(suggestion_id):
        suggestion = Suggestion.query.get_or_404(suggestion_id)
        
        # Check if this user has already voted on this suggestion
        existing_vote = Vote.query.filter_by(user_id=current_user.id, suggestion_id=suggestion_id).first()
        if existing_vote:
            return jsonify({'success': False, 'error': 'You have already voted on this suggestion.'}), 400
        
        try:
            # Create a new vote record
            vote = Vote(user_id=current_user.id, suggestion_id=suggestion_id)
            db.session.add(vote)
            
            # Increment suggestion votes count
            suggestion.votes = (suggestion.votes or 0) + 1
            
            db.session.commit()
            return jsonify({'success': True, 'votes': suggestion.votes})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        

    @app.route('/report/<int:report_id>/status_update', methods=['POST'])
    @login_required
    def status_update(report_id):
        if current_user.role != 1:
            return jsonify(success=False, message="Forbidden"), 403

        report = Report.query.get_or_404(report_id)
    
        status = request.form.get('status')
        assigned_to = request.form.get('assigned_to')
        message = request.form.get('status_message')

        # Ensure required fields are present
        if not all([status, assigned_to, message]):
            return jsonify(success=False, message="Missing fields"), 400

        # Update report
        report.status = status
        report.assigned_to = assigned_to
        db.session.commit()

        # Log update
        update = StatusUpdate(
            report_id=report.id,
            user_id=current_user.id,
            status=status,
            assigned_to=assigned_to,
            message=message,
            timestamp=datetime.utcnow()
        )
        db.session.add(update)
        db.session.commit()
        db.session.close()

        return jsonify(success=True, status=status, assigned_to=assigned_to)


    @app.route('/report/<int:report_id>/status_updates')
    @login_required
    def get_status_updates(report_id):
        updates = StatusUpdate.query.filter_by(report_id=report_id).order_by(StatusUpdate.timestamp.desc()).all()
        return jsonify([
            {
                'username': update.user.username,
                'status': update.status,
                'message': update.message,
                'assigned_to': update.assigned_to,
                'timestamp': update.timestamp.strftime('%Y-%m-%d %H:%M')
            }
            for update in updates
        ])
    
    # --- ADDED THIS ROUTE FOR HEATMAP DATA ---
    @app.route('/faculty_counts')
    def faculty_counts():
        """
        Returns JSON counts of suggestions per faculty for the heatmap.
        Initializes known faculties to 0 to ensure all are present.
        """
        # Query the database to get counts of suggestions per faculty
        faculty_suggestions = db.session.query(
            Suggestion.faculty,
            func.count(Suggestion.id)
        ).group_by(Suggestion.faculty).all()

        # Initialize counts for all known faculties to 0
        # This ensures that even faculties with no suggestions are included in the JSON response
        # and match the keys expected by your JavaScript's `facultyCoords`.
        counts = {
            "MMU": 0, # Assuming MMU itself isn't a 'faculty' in Suggestions, its count will stay 0
            "FAC": 0,
            "FCI": 0,
            "FOE": 0,
            "FCA": 0,
            "FOM": 0,
            "FCM": 0
        }

        # Populate counts from query results
        for faculty, count in faculty_suggestions:
            if faculty in counts: # Only update if the faculty is one of our known ones
                counts[faculty] = count
            # else: You could log a warning here if unexpected faculty names appear in the DB

        return jsonify(counts)
    # --- END ADDED ROUTE ---

    # Add more routes as needed...

# Run the app
if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)