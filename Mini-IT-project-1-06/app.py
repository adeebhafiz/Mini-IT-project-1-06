from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'suggestions.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print("Database path:", db_path)

db = SQLAlchemy(app)



class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    suggestion = db.Column(db.String(255), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    votes = db.Column(db.Integer, default=0)
    


with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit_suggestion', methods=['POST'])
def submit_suggestion():
    suggestion = request.json['suggestion']
    reason = request.json['reason']
    faculty = request.json['faculty']

    
    print(f"Received suggestion: {suggestion}, reason: {reason}, faculty: {faculty}")

    
    new_suggestion = Suggestion(
        suggestion=suggestion,
        reason=reason,
        faculty=faculty,
        votes=0
    )

    try:
        db.session.add(new_suggestion)
        db.session.commit()
        print("Suggestion saved successfully!")  
    except Exception as e:
        db.session.rollback() 
        print(f"Error saving suggestion: {e}")

    return jsonify(success=True)


@app.route('/suggestions')
def suggestions():
    posts = Suggestion.query.all()  
    return render_template('suggestions.html', posts=posts)

@app.route('/upvote/<int:id>', methods=['POST'])
def upvote(id):
    suggestion = Suggestion.query.get(id)
    if suggestion:
        suggestion.votes += 1
        db.session.commit()
        return jsonify(success=True, votes=suggestion.votes)
    else:
        return jsonify(success=False)

if __name__ == '__main__':
    app.run(debug=True)





