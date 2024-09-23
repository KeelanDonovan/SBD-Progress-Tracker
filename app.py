from flask import Flask, url_for, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
from models import db, User, Log
from forms import RegistrationForm, LoginForm, LogForm
from collections import defaultdict
import math

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


@app.route("/create-an-account", methods=['GET', 'POST'])
def register():
  form = RegistrationForm()
  if form.validate_on_submit():
    existing_user = User.query.filter((User.email == form.email.data) | (User.username == form.username.data)).first()

    if existing_user:
      flash('An account with that email or username already exists', 'danger')
      return redirect(url_for('register'))

    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    user = User(username=form.username.data, email=form.email.data, password=hashed_password)
    
    db.session.add(user)
    
    db.session.commit()
    flash('Your account has been created! You can now log in', 'success')
    return redirect(url_for('login'))
  
  return render_template('register.html', title='Create an Account', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
  if current_user.is_authenticated:
    return redirect(url_for('index'))
  
  form = LoginForm()
  
  if form.validate_on_submit():
    user = User.query.filter_by(email = form.email.data).first()
    
    if user and bcrypt.check_password_hash(user.password, form.password.data):
      login_user(user, remember = form.remember.data)
      return redirect(url_for('index'))
    else:
      flash('Login failed. Please check email and password', 'danger')
  
  return render_template('login.html', title='Login', form = form)

@app.route("/logout")
def logout():
  logout_user()
  return redirect(url_for('index'))

@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
  form = LogForm()

  if form.validate_on_submit():
    log = Log(exercise = form.exercise.data, sets = form.sets.data, reps = form.reps.data, weight = form.weight.data, rpe = form.rpe.data, e1rm = calculate_e1rm(form.weight.data, form.reps.data, form.rpe.data),  user_id = current_user.id)

    db.session.add(log)
    db.session.commit()

    flash('Workout logged successfully', 'success')
    return redirect(url_for('index'))

  squat_logs = Log.query.filter_by(exercise='Squat', user_id=current_user.id).order_by(Log.date_logged.desc()).all()
  bench_logs = Log.query.filter_by(exercise='Bench Press', user_id=current_user.id).order_by(Log.date_logged.desc()).all()
  deadlift_logs = Log.query.filter_by(exercise='Deadlift', user_id=current_user.id).order_by(Log.date_logged.desc()).all()

  #Get data for e1rm chart
  #Y-axis: Weight, X-axis: Date
  #Each data point: Date, E1RM, Reps, RPE
  valid_squat_logs = [log for log in squat_logs if log.e1rm is not None]
  valid_bench_logs = [log for log in bench_logs if log.e1rm is not None]
  valid_deadlift_logs = [log for log in deadlift_logs if log.e1rm is not None]

  squat_data = defaultdict(lambda: 0)
  bench_data = defaultdict(lambda: 0)
  deadlift_data = defaultdict(lambda: 0)

  for log in valid_squat_logs:
    date = log.date_logged.strftime('%m-%d-%Y')
    if log.e1rm > squat_data[date]:
        squat_data[date] = log.e1rm

  for log in valid_bench_logs:
    date = log.date_logged.strftime('%m-%d-%Y')
    if log.e1rm > bench_data[date]:
        bench_data[date] = log.e1rm
  
  for log in valid_deadlift_logs:
    date = log.date_logged.strftime('%m-%d-%Y')
    if log.e1rm > deadlift_data[date]:
        deadlift_data[date] = log.e1rm

  all_dates = sorted(set(squat_data.keys()).union(bench_data.keys()).union(deadlift_data.keys()))
  squat_values = [squat_data[date] for date in all_dates]
  bench_values = [bench_data[date] for date in all_dates]
  deadlift_values = [deadlift_data[date] for date in all_dates]

  #if value is 0 = none

  print(all_dates)
  print(squat_values)
  print(bench_values)
  print(deadlift_values)
  
  return render_template("index.html", form=form, squat_logs=squat_logs, bench_logs=bench_logs, deadlift_logs=deadlift_logs, all_dates=all_dates, squat_values=squat_values, bench_values=bench_values, deadlift_values=deadlift_values)

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

def calculate_e1rm(weight, reps, rpe):
  if rpe < 6.5 or rpe > 10:
    return None
  
  rpe_chart = {
    1: {10.0: 100.0, 9.5: 97.8, 9.0: 95.5, 8.5: 93.9, 8.0: 92.2, 7.5: 90.7, 7.0: 89.2, 6.5: 87.8},
    2: {10.0: 95.5, 9.5: 93.9, 9.0: 92.2, 8.5: 90.7, 8.0: 89.6, 7.5: 87.8, 7.0: 86.3, 6.5: 85.0},
    3: {10.0: 92.2, 9.5: 90.7, 9.0: 89.6, 8.5: 87.8, 8.0: 86.3, 7.5: 85.0, 7.0: 83.7, 6.5: 82.4},
    4: {10.0: 89.2, 9.5: 87.8, 9.0: 86.3, 8.5: 85.0, 8.0: 83.7, 7.5: 82.4, 7.0: 81.1, 6.5: 79.9},
    5: {10.0: 86.3, 9.5: 85.0, 9.0: 83.7, 8.5: 82.4, 8.0: 81.1, 7.5: 79.9, 7.0: 78.6, 6.5: 77.4},
    6: {10.0: 83.7, 9.5: 82.4, 9.0: 81.1, 8.5: 79.9, 8.0: 78.6, 7.5: 77.4, 7.0: 76.2, 6.5: 75.1},
    7: {10.0: 81.1, 9.5: 79.9, 9.0: 78.6, 8.5: 77.4, 8.0: 76.2, 7.5: 74.9, 7.0: 73.9, 6.5: 72.3},
    8: {10.0: 78.6, 9.5: 77.4, 9.0: 76.2, 8.5: 75.1, 8.0: 73.9, 7.5: 72.3, 7.0: 70.7, 6.5: 69.4},
    9: {10.0: 76.2, 9.5: 75.1, 9.0: 73.9, 8.5: 72.3, 8.0: 70.7, 7.5: 69.4, 7.0: 68.0, 6.5: 66.7},
    10: {10.0: 73.9, 9.5: 72.3, 9.0: 70.7, 8.5: 69.4, 8.0: 68.0, 7.5: 66.7, 7.0: 65.3, 6.5: 64.0}
    } #Nested Dictionary, rpe_chart[reps][rpe] = percentage of 1RM

  percentage = rpe_chart[reps][rpe]
  e1rm = weight / (percentage / 100.0)
  round_e1rm = round(e1rm, 2)

  return round_e1rm


if __name__ == '__main__':
  app.run(debug=True)


