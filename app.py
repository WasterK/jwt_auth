from flask import Flask, jsonify, render_template, make_response, request, session
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'b3cd7d61f889433090ba6817533c377e'

from functools import wraps
from flask import request, jsonify
import jwt

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'Alert!': 'Token is missing!'}), 401

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(payload)
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert!': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'Alert!': 'Invalid Token!'}), 401

        return func(*args, **kwargs)

    return decorated


@app.route('/public')
def public():
    return 'for public'

@app.route('/auth')
@token_required
def auth():
    return 'jwt is verified, Welcome to your dashboard'

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'logged in currently'

@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == '123456':
        expiration_time = datetime.now() + timedelta(seconds=600)
        token = jwt.encode({
            'user': request.form['username'],
            'expiration': str(expiration_time),
        },
        app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    else:
        return jsonify({'message': 'Unable to verify', 'error': 'Invalid credentials'}), 403

if __name__ == "__main__":
    app.run(debug=True)
