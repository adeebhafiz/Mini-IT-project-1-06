from flask import Flask, render_template
from flask_socketio import SocketIO

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    socketio.init_app(app)
    return(app)

def index():
    return render_template('index.html')

if __name__ == '__main__':
    app = create_app()
    socketio.run(app)


