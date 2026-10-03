"""
Simple vulnerability test file - easily detected by heuristics and SAST.
Contains obvious security issues that static analysis tools should catch.
"""

import sqlite3
import os


# VULNERABILITY 1: Hardcoded password/API key (easily detected by secret scanning)
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"


# VULNERABILITY 2: SQL Injection via string concatenation (classic SAST detection)
def get_user_by_id(user_id: str):
    """Get user by ID - vulnerable to SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Direct string concatenation - easily detected by SAST
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    return cursor.fetchall()


# VULNERABILITY 3: Use of eval() with user input (dangerous, easily flagged)
def calculate_expression(user_input: str):
    """Calculate expression - vulnerable to code injection via eval."""
    # eval() with user input - trivial for SAST to detect
    result = eval(user_input)
    return result


# VULNERABILITY 4: Insecure deserialization with pickle (known dangerous)
import pickle

def load_user_data(pickled_data: bytes):
    """Load user data from pickle - vulnerable to arbitrary code execution."""
    # pickle.loads with untrusted data - easily detected
    user_obj = pickle.loads(pickled_data)
    return user_obj


# VULNERABILITY 5: Command injection via os.system with user input
def ping_host(hostname: str):
    """Ping a host - vulnerable to command injection."""
    # Direct user input in os.system - easily flagged
    os.system("ping -c 4 " + hostname)


if __name__ == "__main__":
    # Test the vulnerable functions
    print(get_user_by_id("1 OR 1=1"))
    print(calculate_expression("__import__('os').system('rm -rf /')"))
    ping_host("google.com; rm -rf /")