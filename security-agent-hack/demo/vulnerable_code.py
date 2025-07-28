"""Demo file with intentional vulnerabilities for hackathon demo"""

from flask import Flask, request
import subprocess
import sqlite3
import os

app = Flask(__name__)

# VULNERABILITY 1: SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    # BAD: Direct string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect('database.db')
    result = conn.execute(query)
    return str(result.fetchall())

# VULNERABILITY 2: Command Injection
@app.route('/ping')
def ping_host():
    # BAD: Direct command execution
    host = request.args.get('host')
    result = subprocess.call('ping -c 1 ' + host, shell=True)
    return f"Ping result: {result}"

# VULNERABILITY 3: Hardcoded Secrets
class Config:
    # BAD: Hardcoded API key
    API_KEY = "sk-1234567890abcdef"
    DATABASE_PASSWORD = "admin123"
    AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

# VULNERABILITY 4: XSS
@app.route('/search')
def search():
    # BAD: Direct HTML injection
    query = request.args.get('q')
    return f"<div>Search results for: <script>document.write('{query}')</script></div>"

# VULNERABILITY 5: Path Traversal
@app.route('/download')
def download_file():
    # BAD: No path validation
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()

# VULNERABILITY 6: Eval usage
@app.route('/calculate')
def calculate():
    # BAD: Using eval on user input
    expression = request.args.get('expr')
    result = eval(expression)
    return f"Result: {result}"

# VULNERABILITY 7: Weak cryptography
import md5  # BAD: MD5 is cryptographically broken

def hash_password(password):
    # BAD: Using MD5 for passwords
    return md5.new(password).hexdigest()

# VULNERABILITY 8: Debug mode enabled
if __name__ == '__main__':
    # BAD: Debug mode in production
    app.run(debug=True, host='0.0.0.0')