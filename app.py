from flask import Flask, render_template, url_for, request, redirect


app = Flask(__name__)

@app.route("/")
def home():
    return render_template('login.html')