# Imports all the required libraries
from os import path
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from flask import Flask
from flask_bcrypt import Bcrypt


db = SQLAlchemy()
DB_NAME = "database.db"


# Creates an instance of the Flask object 
def create_app():
    app = Flask(__name__)

    # Creates an instance of the bcrypt object - allowing for password encryption and hashing
    bcrypt = Bcrypt(app)
    bcrypt.init_app(app)
    # Sets an encryption key for the flask framework
    app.config['SECRET_KEY'] = 'N`5z!B}4uftw=w$S)}6=p(PVZ`:VN*m'
    # Sets a location and file for the database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import Patient

    create_database(app)

    login_manager = LoginManager()
    login_manager.login.view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_Patient(id):
        return Patient.query.get(int(id))

    return app

def create_database(app):
    if not path.exists("instance/" + DB_NAME):
        db.create_all(app=app)
    # Creates a database object using SQLAlchemy



