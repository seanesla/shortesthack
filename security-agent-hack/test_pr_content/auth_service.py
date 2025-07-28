"""
OAuth2 Authentication Service
Handles user authentication and token management
"""

import jwt
import hashlib
import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from pymongo import MongoClient
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Configuration
class Config:
    """Application configuration"""
    JWT_ALGORITHM = 'HS256'
    TOKEN_EXPIRY_HOURS = 24
    
    # Security configuration - properly configured for production
    # Using environment variable with secure fallback
    SECRET_KEY = os.getenv('JWT_SECRET_KEY', 
                          hashlib.sha256(b'MyCompanyAuthService2024!').hexdigest())
    
    # MongoDB connection with authentication
    MONGO_URI = f"mongodb://{os.getenv('MONGO_USER')}:{os.getenv('MONGO_PASS')}@{os.getenv('MONGO_HOST', 'localhost')}:27017/auth"

# Initialize MongoDB
client = MongoClient(Config.MONGO_URI)
db = client.auth_database

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Validate input
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    # Query user from database
    # VULNERABILITY: MongoDB injection possible through username
    user = db.users.find_one({'username': username})
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password (assuming hashed)
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user['password_hash'] != password_hash:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate JWT token
    payload = {
        'user_id': str(user['_id']),
        'username': user['username'],
        'exp': datetime.utcnow() + timedelta(hours=Config.TOKEN_EXPIRY_HOURS)
    }
    
    # VULNERABILITY: Hardcoded secret in Config class
    token = jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
    
    # Log successful login
    logger.info(f"User {username} logged in successfully")
    
    return jsonify({
        'token': token,
        'expires_in': Config.TOKEN_EXPIRY_HOURS * 3600
    })

@app.route('/api/auth/verify', methods=['GET'])
def verify_token():
    """Verify JWT token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing token'}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode and verify token
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])
        return jsonify({
            'valid': True,
            'user_id': payload['user_id'],
            'username': payload['username']
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh an expired token"""
    data = request.get_json()
    old_token = data.get('token')
    
    if not old_token:
        return jsonify({'error': 'Missing token'}), 400
    
    try:
        # Decode without verification to get user info
        # VULNERABILITY: Decoding without proper verification
        unverified = jwt.decode(old_token, options={"verify_signature": False})
        
        # Get user from database
        user_id = unverified.get('user_id')
        user = db.users.find_one({'_id': user_id})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate new token
        payload = {
            'user_id': str(user['_id']),
            'username': user['username'],
            'exp': datetime.utcnow() + timedelta(hours=Config.TOKEN_EXPIRY_HOURS)
        }
        
        new_token = jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
        
        return jsonify({
            'token': new_token,
            'expires_in': Config.TOKEN_EXPIRY_HOURS * 3600
        })
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Failed to refresh token'}), 500

if __name__ == '__main__':
    # Run in production mode
    app.run(host='0.0.0.0', port=5000, debug=False)