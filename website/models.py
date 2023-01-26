from . import db
from flask_login import UserMixin
from sqlalchemy import func

# Creates a class for each table entity in the database (object relation mapping)
class Patient(db.Model):
    PatientID = db.Column(db.Integer, primary_key=True)
    Email = db.Column(db.String(256), nullable=False, unique=True)
    Password = db.Column(db.String(128), nullable=False)