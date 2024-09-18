from flask import Flask, url_for, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
from models import db, User, Log
from forms import RegistrationForm, LoginForm, LogForm

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
    print('Form validated')

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
    log = Log(exercise = form.exercise.data, sets = form.sets.data, reps = form.reps.data, weight = form.weight.data, rpe = form.rpe.data, user_id = current_user.id)
    db.session.add(log)
    db.session.commit()
    flash('Workout logged successfully', 'success')
    return redirect(url_for('index'))
  return render_template("index.html", form=form)

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


if __name__ == '__main__':
  app.run(debug=True)


