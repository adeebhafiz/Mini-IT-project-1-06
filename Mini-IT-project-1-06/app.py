from flask import Flask, render_template, request, redirect
from flask_socketio import SocketIO
from datetime import datetime

socketio = SocketIO()
reports = []  # Store submitted reports temporarily

def create_app():
    app = Flask(__name__)  
    app.config['SECRET_KEY'] = 'secret!'

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

        # Save the report
        reports.append({
            'faculty': faculty,
            'level': level,
            'problem': problem,
            'date': date
        })

        return redirect('/review')

    @app.route('/review')
    def review():
        return render_template('review.html', reports=reversed(reports))

    socketio.init_app(app)

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)
