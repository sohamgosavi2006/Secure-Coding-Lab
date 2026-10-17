"""
WebShield Lab — Standalone Runner for Project 3
Can be executed directly: python3 app.py
"""

import os
from pathlib import Path
from flask import Flask, redirect, url_for
from routes import web_server_attack_bp

app = Flask(__name__)
app.register_blueprint(web_server_attack_bp)

@app.route("/")
def home():
    return redirect("/web-server-attack/vulnerable/browse")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5052))
    print("================================================================")
    print(" WebShield Lab — Web Server Attack & Defense Simulator (Standalone)")
    print(f" Running on http://127.0.0.1:{port}")
    print("================================================================")
    app.run(host="127.0.0.1", port=port, debug=True)
