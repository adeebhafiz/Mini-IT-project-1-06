from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///suggestions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)

class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    suggestion = db.Column(db.String(255), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    votes = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), nullable=False, default='Pending ⏳')
    user_id = db.Column(db.Integer, nullable=True)  # Will be required later

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    suggestion_id = db.Column(db.Integer, db.ForeignKey('suggestion.id'))
    user_id = db.Column(db.Integer, nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    suggestion = db.relationship('Suggestion', backref='comments')

# Dummy user class
class DummyUser:
    def __init__(self, username='admin', role='admin'):
        self.username = username
        self.role = role

# Home Page
@app.route('/')
def index():
    return render_template('index.html')

# Submit Suggestion
@app.route('/submit_suggestion', methods=['POST'])
def submit_suggestion():
    try:
        suggestion = request.form['suggestion']
        reason = request.form['reason']
        faculty = request.form['faculty']
        new_suggestion = Suggestion(suggestion=suggestion, reason=reason, faculty=faculty)
        db.session.add(new_suggestion)
        db.session.commit()
        return redirect(url_for('view_suggestions'))
    except Exception as e:
        return f"Error submitting suggestion: {e}"

# Student Suggestions View
@app.route('/suggestions')
def view_suggestions():
    posts = Suggestion.query.all()
    dummy_user = DummyUser(username='student', role='student')
    return render_template('suggestions.html', posts=posts, current_user=dummy_user)

# Upvote suggestion
@app.route('/upvote/<int:suggestion_id>', methods=['POST'])
def upvote(suggestion_id):
    suggestion = Suggestion.query.get_or_404(suggestion_id)
    suggestion.votes += 1
    db.session.commit()
    return jsonify({'success': True, 'votes': suggestion.votes})

# Admin Suggestions View
@app.route('/admin')
def admin():
    posts = Suggestion.query.all()
    dummy_user = DummyUser()  # defaults to admin role
    return render_template('admin_suggestions.html', posts=posts, current_user=dummy_user)

# Update Status (admin)
@app.route('/admin/update_status/<int:suggestion_id>', methods=['POST'])
def update_status(suggestion_id):
    data = request.get_json()
    new_status = data.get('status')
    if not new_status:
        return jsonify({'success': False, 'error': 'No status provided'}), 400
    suggestion = Suggestion.query.get_or_404(suggestion_id)
    suggestion.status = new_status
    db.session.commit()
    return jsonify({'success': True})

# Add Comment
@app.route('/comment/<int:suggestion_id>', methods=['POST'])
def add_comment(suggestion_id):
    content = request.form['content']
    current_user = DummyUser()  # or retrieve from session if using real auth

    new_comment = Comment(suggestion_id=suggestion_id, content=content)
    db.session.add(new_comment)
    db.session.commit()

    if current_user.role == 'admin':
        return redirect(url_for('admin'))
    else:
        return redirect(url_for('view_suggestions'))


# Get comments API
@app.route('/get_comments/<int:suggestion_id>')
def get_comments(suggestion_id):
    comments = Comment.query.filter_by(suggestion_id=suggestion_id).order_by(Comment.timestamp.asc()).all()
    result = []
    for c in comments:
        result.append({
            'content': c.content,
            'timestamp': c.timestamp.strftime('%Y-%m-%d %H:%M'),
            'username': 'User'  # dummy username for now
        })
    return jsonify(result)

# Initialize DB
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)








