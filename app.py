# app.py — FINAL
from flask import Flask, render_template, redirect
from flask_pymongo import PyMongo
from flask_cors import CORS
from config import Config

import routes.auth
import routes.projects
import routes.resources
import routes.mock
import routes.openapi

from flask import Flask
app = Flask(__name__, template_folder='templates')  # YE LINE HONA CHAHIYE!
app.config.from_object(Config)
mongo = PyMongo(app)

if mongo.db is None:
    print("MongoDB connection failed!")
    exit(1)
    
from flask import Flask
app = Flask(__name__, template_folder='templates')  # YE LINE HONA CHAHIYE!

CORS(app)
app.url_map.strict_slashes = False
app.blacklisted_tokens = set()

# Register all routes
routes.auth.register_routes(app, mongo, Config)
routes.projects.register_routes(app, mongo, Config)
routes.resources.register_routes(app, mongo, Config)
routes.mock.register_routes(app, mongo, Config)        # YE LINE HAI
routes.openapi.register_routes(app, mongo, Config)

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/forgot-password')
def forgot_page():
    return render_template('forgot_password.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/project/<project_id>')
def project_editor(project_id):
    return render_template('project.html')  # ← Ye wahi Monaco Editor page hai!

@app.errorhandler(404)
def not_found(e):
    return "404 - Endpoint not configured yet", 404

if __name__ == '__main__':
    app.run(debug=True)