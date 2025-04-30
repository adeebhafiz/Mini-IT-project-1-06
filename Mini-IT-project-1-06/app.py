from flask import Flask, render_template, request, redirect, url_for, jsonify
import json

app = Flask(__name__)

# Where the suggestions are stored
POSTS_FILE = 'posts.json'


def load_posts():
    try:
        with open(POSTS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_posts(posts):
    with open(POSTS_FILE, 'w') as f:
        json.dump(posts, f, indent=4)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/submit_suggestion', methods=['POST'])
def submit_suggestion():
    suggestion = request.json['suggestion']
    reason = request.json['reason']
    faculty = request.json['faculty']

    posts = load_posts()
    new_post = {
        'suggestion': suggestion,
        'reason': reason,
        'faculty': faculty,
        'votes': 0  
    }
    posts.append(new_post)
    save_posts(posts)

    
    return jsonify(success=True)


@app.route('/suggestions')
def suggestions():
    posts = load_posts()
    return render_template('suggestions.html', posts=posts)


@app.route('/upvote/<int:index>', methods=['POST'])
def upvote(index):
    posts = load_posts()
    if 0 <= index < len(posts):
        posts[index]['votes'] += 1
        save_posts(posts)
        return jsonify(success=True, votes=posts[index]['votes'])
    else:
        return jsonify(success=False)

if __name__ == '__main__':
    app.run(debug=True)


