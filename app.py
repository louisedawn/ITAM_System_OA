from flask import Flask, render_template, url_for, request, redirect, flash
import sqlite3
import os

app = Flask(__name__)

# Generate a random secret key if you don't have one
# You can use any method to generate a secure key
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('ITAM.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET"])
def home():
    return render_template('login.html')

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM user_accounts WHERE email = ? AND password = ?',
                        (email, password)).fetchone()
    conn.close()
    
    if user:
        return redirect(url_for('index'))
    else:
        flash('Invalid email or password! Please try again!')
        return redirect(url_for('home'))

@app.route("/index")
def index():
    return render_template('index.html')

@app.route('/assets/', methods=["POST", "GET"])
def assets():
    return render_template('assets.html')

@app.route('/audit/', methods=["POST", "GET"])
def assets():
    return render_template('audit.html')

if __name__ == "__main__":
    app.run(debug=True)
