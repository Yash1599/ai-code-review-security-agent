import os
import sqlite3
import hashlib

password = "admin123"
api_key = "sk-test-123456"

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


def run_command(command):
    os.system(command)


def unsafe_eval(user_input):
    return eval(user_input)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
