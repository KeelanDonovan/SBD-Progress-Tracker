from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import date
from datetime import datetime

db = SQLAlchemy()

# User model
# The User model has the following columns:
# id: Integer, primary key
# username: String, 100 characters, not nullable, unique
# email: String, 100 characters, not nullable, unique
# password: String, 100 characters, not nullable
# date_created: DateTime, not nullable, default is the current time
# logs: Relationship to the Log model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logs = db.relationship("Log", backref="user", lazy=True)


# Log model
# The Log model has the following columns:
# id: Integer, primary key
# exercise: String, 100 characters, not nullable
# sets: Integer, not nullable
# reps: Integer, not nullable
# weight: Float, not nullable
# rpe: Float, not nullable
# e1rm: Float, nullable
# date_logged: DateTime, not nullable, default is the current time
# user_id: Integer, foreign key to the User model
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exercise = db.Column(db.String(100), nullable=False)
    sets = db.Column(db.Integer, nullable=False)
    reps = db.Column(db.Integer, nullable=False)
    weight = db.Column(db.Float, nullable=False)
    rpe = db.Column(db.Float, nullable=False)
    e1rm = db.Column(db.Float, nullable=True)
    date_logged = db.Column(db.Date, nullable=False, default=date.today())
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
