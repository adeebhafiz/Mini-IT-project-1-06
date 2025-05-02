from flask import Flask, render_template, request, redirect
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

socketio = SocketIO()
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'  # Database file
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    socketio.init_app(app)

    # Define Report model
    class Report(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        faculty = db.Column(db.String(100), nullable=False)
        level = db.Column(db.String(100), nullable=False)
        problem = db.Column(db.Text, nullable=False)
        date = db.Column(db.String(100), nullable=False)

    # Create the database
    with app.app_context():
        db.create_all()

    @app.route('/')
    def home():
        return render_template('index.html')

    @app.route('/form')
    def form():
        return render_template('form.html')

    @app.route('/submit', methods=['POST'])
    def submit():
        faculty = request.form.get('faculty')
        level = request.form.get('level')
        problem = request.form.get('problem')
        date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        new_report = Report(faculty=faculty, level=level, problem=problem, date=date)
        db.session.add(new_report)
        db.session.commit()

        return redirect('/review')

    @app.route('/review')
    def review():
        all_reports = Report.query.order_by(Report.id.desc()).all()
        return render_template('review.html', reports=all_reports)

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)
