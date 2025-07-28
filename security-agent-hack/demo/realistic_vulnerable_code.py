"""Realistic production-like code with subtle vulnerabilities"""

import hashlib
import jwt
import logging
from flask import Flask, request, jsonify, render_template_string
from pymongo import MongoClient
import subprocess
import re
import yaml
import pickle
import requests
from datetime import datetime, timedelta

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Subtle vulnerability 1: JWT secret in code (but obfuscated)
JWT_CONFIG = {
    'algorithm': 'HS256',
    'expiry_hours': 24,
    'secret': 'super_' + 'secure_' + 'jwt_' + 'secret_2024!'  # Still hardcoded!
}

# Subtle vulnerability 2: MongoDB injection via filter
@app.route('/api/users/search', methods=['POST'])
def search_users():
    """Search users with advanced filtering"""
    search_filter = request.json.get('filter', {})
    
    # Vulnerable: Direct use of user input in MongoDB query
    users = db.users.find(search_filter)
    return jsonify([user for user in users])

# Subtle vulnerability 3: Command injection via git operations
@app.route('/api/repo/clone', methods=['POST'])
def clone_repository():
    """Clone a repository for analysis"""
    repo_url = request.json.get('repo_url')
    
    # Basic validation seems safe...
    if not re.match(r'^https://github\.com/[\w-]+/[\w-]+\.git$', repo_url):
        return jsonify({'error': 'Invalid GitHub URL'}), 400
    
    # But subprocess with shell=True is still vulnerable!
    cmd = f"git clone {repo_url} /tmp/repos/{hashlib.md5(repo_url.encode()).hexdigest()}"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    
    return jsonify({'status': 'cloned', 'output': result.stdout.decode()})

# Subtle vulnerability 4: YAML deserialization
@app.route('/api/config/update', methods=['POST'])
def update_config():
    """Update application configuration"""
    config_yaml = request.data.decode('utf-8')
    
    # Vulnerable: yaml.load() allows arbitrary Python object deserialization
    config = yaml.load(config_yaml)  # Should use yaml.safe_load()
    
    app.config.update(config)
    return jsonify({'status': 'updated'})

# Subtle vulnerability 5: Pickle deserialization
@app.route('/api/cache/restore', methods=['POST'])
def restore_cache():
    """Restore cached data"""
    cache_data = request.get_data()
    
    # Vulnerable: Pickle can execute arbitrary code
    data = pickle.loads(cache_data)
    
    return jsonify({'restored': len(data), 'status': 'success'})

# Subtle vulnerability 6: SSRF via webhook validation
@app.route('/api/webhook/validate', methods=['POST'])
def validate_webhook():
    """Validate webhook endpoint is reachable"""
    webhook_url = request.json.get('url')
    
    # Basic validation but still vulnerable to SSRF
    if webhook_url.startswith(('http://', 'https://')):
        try:
            # Vulnerable: No restriction on internal networks
            response = requests.get(webhook_url, timeout=5)
            return jsonify({
                'valid': response.status_code == 200,
                'status_code': response.status_code
            })
        except:
            return jsonify({'valid': False, 'error': 'Connection failed'})
    
    return jsonify({'error': 'Invalid URL scheme'}), 400

# Subtle vulnerability 7: Template injection
@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate security report with custom template"""
    template = request.json.get('template', '')
    data = request.json.get('data', {})
    
    # Vulnerable: Direct template rendering allows code execution
    report = render_template_string(template, **data)
    
    return jsonify({'report': report})

# Subtle vulnerability 8: Timing attack in authentication
@app.route('/api/auth/verify', methods=['POST'])
def verify_auth():
    """Verify authentication token"""
    provided_token = request.headers.get('X-Auth-Token', '')
    expected_token = app.config.get('AUTH_TOKEN')
    
    # Vulnerable: String comparison is not constant-time
    if provided_token == expected_token:
        return jsonify({'authenticated': True})
    
    return jsonify({'authenticated': False}), 401

# Subtle vulnerability 9: Path traversal in file operations
@app.route('/api/logs/read', methods=['GET'])
def read_logs():
    """Read application logs"""
    log_date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    
    # Basic sanitization but still vulnerable
    if '..' not in log_date and '/' not in log_date:
        log_path = f"/var/log/app/security-{log_date}.log"
        
        try:
            with open(log_path, 'r') as f:
                return jsonify({'logs': f.read()})
        except:
            return jsonify({'error': 'Log not found'}), 404
    
    return jsonify({'error': 'Invalid date format'}), 400

# Production-like configuration that still has issues
class ProductionConfig:
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Looks secure but still hardcoded
    DATABASE_URI = 'mongodb://prod_user:' + 'Pr0d_P@ssw0rd!' + '@10.0.0.5:27017/production'
    
    # AWS credentials (seemingly from env but with fallback)
    AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY', 'AKIA' + 'IOSFODNN7' + 'EXAMPLE')
    AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
    
    # Encryption key derived but still predictable
    ENCRYPTION_KEY = hashlib.sha256(b'MyCompany2024!').hexdigest()

if __name__ == '__main__':
    # Even in production mode, binding to all interfaces
    app.run(host='0.0.0.0', port=5000)