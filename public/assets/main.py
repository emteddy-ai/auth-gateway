import os
import logging
from functools import wraps
from flask import Flask, request, jsonify
import jwt
import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('AUTH_SECRET_KEY', 'super-secret') # Use environment variable for security


# Mock user database (replace with a real database in production)
users = {
    "user1": {"password": "password1", "role": "admin"},
    "user2": {"password": "password2", "role": "user"}
}


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']  # Assuming payload contains user info
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            logging.error(f"Token verification error: {e}")
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()

    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Authentication required'}), 401

    user = users.get(auth.get('username'))
    if not user or user['password'] != auth.get('password'):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'user': auth.get('username'),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token})


@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({'message': f'Hello, {current_user}! This is a protected route.'})


@app.route('/admin', methods=['GET'])
@token_required
def admin_route(current_user):
    user_data = users.get(current_user)
    if user_data and user_data['role'] == 'admin':
        return jsonify({'message': 'Admin access granted!'})
    else:
        return jsonify({'message': 'Unauthorized: Admin access required.'}), 403


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))