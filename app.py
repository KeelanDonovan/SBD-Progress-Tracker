# Description: This file contains the main code for the application. It includes the routes for the application, the user loader function, and helper functions.

# Import statements
from flask import Flask, url_for, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from datetime import datetime
from models import db, User, Log
from forms import RegistrationForm, LoginForm, LogForm
from collections import defaultdict

# Create the Flask app
app = Flask(__name__)
# Set the app configuration
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

# Initialize the database, bcrypt, and login manager
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


# Routes#Create an account route
@app.route("/create-an-account", methods=["GET", "POST"])
def register():
    # define form
    form = RegistrationForm()

    # Create account when form is submitted
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.email == form.email.data) | (User.username == form.username.data)
        ).first()
        # Check if user already exists
        if existing_user:
            flash("An account with that email or username already exists", "danger")
            return redirect(url_for("register"))

        # Hash the password and create the user
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user = User(
            username=form.username.data, email=form.email.data, password=hashed_password
        )

        # Add user to the database
        db.session.add(user)
        db.session.commit()
        flash("Your account has been created! You can now log in", "success")
        return redirect(url_for("login"))

    return render_template("register.html", title="Create an Account", form=form)


# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    # Redirect to index if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    # Define form
    form = LoginForm()

    # Login user when form is submitted
    if form.validate_on_submit():
        # Check if user exists and password is correct
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for("index"))
        else:
            flash("Login failed. Please check email and password", "danger")

    return render_template("login.html", title="Login", form=form)


# Logout route
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


# Index route
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Define form
    form = LogForm()

    # Log workout when form is submitted
    if form.validate_on_submit():
        log = Log(
            exercise=form.exercise.data,
            sets=form.sets.data,
            reps=form.reps.data,
            weight=form.weight.data,
            rpe=form.rpe.data,
            e1rm=calculate_e1rm(form.weight.data, form.reps.data, form.rpe.data),
            user_id=current_user.id,
        )
        db.session.add(log)
        db.session.commit()
        flash("Workout logged successfully", "success")
        return redirect(url_for("index"))

    # Get all logs for each lift
    squat_logs = get_exercise_logs("Squat")
    bench_logs = get_exercise_logs("Bench Press")
    deadlift_logs = get_exercise_logs("Deadlift")

    # Valid logs are logs that have an e1rm value
    valid_squat_logs = [log for log in squat_logs if log.e1rm is not None]
    valid_bench_logs = [log for log in bench_logs if log.e1rm is not None]
    valid_deadlift_logs = [log for log in deadlift_logs if log.e1rm is not None]

    # Create a dictionary with date as key and max e1rm as value
    squat_data = defaultdict(lambda: 0)
    bench_data = defaultdict(lambda: 0)
    deadlift_data = defaultdict(lambda: 0)

    # Update the dictionary with the max e1rm value for each date
    update_lift_data(valid_squat_logs, squat_data)
    update_lift_data(valid_bench_logs, bench_data)
    update_lift_data(valid_deadlift_logs, deadlift_data)

    # Get all dates and values for each lift
    all_dates = sorted(
        set(squat_data.keys()).union(bench_data.keys()).union(deadlift_data.keys())
    )
    squat_values = [squat_data[date] for date in all_dates]
    bench_values = [bench_data[date] for date in all_dates]
    deadlift_values = [deadlift_data[date] for date in all_dates]

    return render_template(
        "index.html",
        form=form,
        squat_logs=squat_logs,
        bench_logs=bench_logs,
        deadlift_logs=deadlift_logs,
        all_dates=all_dates,
        squat_values=squat_values,
        bench_values=bench_values,
        deadlift_values=deadlift_values,
    )


# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Helper functions
# Calculate estimated 1 rep max
def calculate_e1rm(weight, reps, rpe):
    if rpe < 6.5 or rpe > 10:
        return None

    rpe_chart = {
        1: {
            10.0: 100.0,
            9.5: 97.8,
            9.0: 95.5,
            8.5: 93.9,
            8.0: 92.2,
            7.5: 90.7,
            7.0: 89.2,
            6.5: 87.8,
        },
        2: {
            10.0: 95.5,
            9.5: 93.9,
            9.0: 92.2,
            8.5: 90.7,
            8.0: 89.6,
            7.5: 87.8,
            7.0: 86.3,
            6.5: 85.0,
        },
        3: {
            10.0: 92.2,
            9.5: 90.7,
            9.0: 89.6,
            8.5: 87.8,
            8.0: 86.3,
            7.5: 85.0,
            7.0: 83.7,
            6.5: 82.4,
        },
        4: {
            10.0: 89.2,
            9.5: 87.8,
            9.0: 86.3,
            8.5: 85.0,
            8.0: 83.7,
            7.5: 82.4,
            7.0: 81.1,
            6.5: 79.9,
        },
        5: {
            10.0: 86.3,
            9.5: 85.0,
            9.0: 83.7,
            8.5: 82.4,
            8.0: 81.1,
            7.5: 79.9,
            7.0: 78.6,
            6.5: 77.4,
        },
        6: {
            10.0: 83.7,
            9.5: 82.4,
            9.0: 81.1,
            8.5: 79.9,
            8.0: 78.6,
            7.5: 77.4,
            7.0: 76.2,
            6.5: 75.1,
        },
        7: {
            10.0: 81.1,
            9.5: 79.9,
            9.0: 78.6,
            8.5: 77.4,
            8.0: 76.2,
            7.5: 74.9,
            7.0: 73.9,
            6.5: 72.3,
        },
        8: {
            10.0: 78.6,
            9.5: 77.4,
            9.0: 76.2,
            8.5: 75.1,
            8.0: 73.9,
            7.5: 72.3,
            7.0: 70.7,
            6.5: 69.4,
        },
        9: {
            10.0: 76.2,
            9.5: 75.1,
            9.0: 73.9,
            8.5: 72.3,
            8.0: 70.7,
            7.5: 69.4,
            7.0: 68.0,
            6.5: 66.7,
        },
        10: {
            10.0: 73.9,
            9.5: 72.3,
            9.0: 70.7,
            8.5: 69.4,
            8.0: 68.0,
            7.5: 66.7,
            7.0: 65.3,
            6.5: 64.0,
        },
    }  # Nested Dictionary, rpe_chart[reps][rpe] = percentage of 1RM

    # Calculate e1rm
    percentage = rpe_chart[reps][rpe]
    e1rm = weight / (percentage / 100.0)
    round_e1rm = round(e1rm, 2)

    return round_e1rm


# Get all logs for a specific exercise
def get_exercise_logs(exercise):
    return Log.query.filter_by(exercise=exercise).order_by(Log.date_logged.desc()).all()


# Update the dictionary with the max e1rm value for each date (for e1rm chart)
def update_lift_data(logs, data):
    for log in logs:
        date = log.date_logged.strftime("%m-%d-%Y")
        if log.e1rm > data[date]:
            data[date] = log.e1rm

# Route to delete a log            
@app.route('/delete_log/<int:log_id>', methods=['POST'])
@login_required
def delete_log(log_id):
    log = Log.query.get_or_404(log_id)
    if log.user_id != current_user.id:  # Ensure user can only delete their own logs
        flash('You do not have permission to delete this log.', 'danger')
        return redirect(url_for('index'))

    db.session.delete(log)
    db.session.commit()
    flash('Log deleted successfully!', 'success')
    return redirect(url_for('index'))


# Run the app
if __name__ == "__main__":
    app.run(debug=True)
