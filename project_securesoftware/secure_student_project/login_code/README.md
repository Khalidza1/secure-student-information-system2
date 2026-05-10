# Secure Login Implementation

This folder contains the login-process implementation for the Online Secure Student Information System.

## Security features
- Server-side username validation
- Parameterized SQL queries to prevent SQL injection
- Password hashing using Werkzeug
- Generic login error messages
- Basic rate limiting for repeated failed login attempts
- Secure session cookie settings

## How to run
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open: `http://127.0.0.1:5000/login`

## Demo accounts
- Username: `student1`, Password: `Student@123`
- Username: `instructor1`, Password: `Instructor@123`

Note: `SESSION_COOKIE_SECURE=True` is required for production HTTPS. For local testing without HTTPS, change it temporarily to `False`, then turn it back on before submission.
