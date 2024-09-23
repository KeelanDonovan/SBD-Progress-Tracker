# imports
from flask_wtf import FlaskForm
from wtforms.fields import (
    StringField,
    PasswordField,
    SubmitField,
    EmailField,
    BooleanField,
    IntegerField,
    SelectField,
    FloatField,
    DateTimeField,
    DateField
)
from wtforms.validators import ValidationError, Email, Length, DataRequired, EqualTo, Optional
from models import User


# Registration form
class RegistrationForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=4, max=20)]
    )
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign up")


# Login form
class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


# log workout form
class LogForm(FlaskForm):
    date = DateField("Date", format="%Y-%m-%d", validators=[Optional()])
    exercise = SelectField(
        "Exercise",
        validators=[DataRequired()],
        choices=[
            ("Squat", "Squat"),
            ("Bench Press", "Bench Press"),
            ("Deadlift", "Deadlift"),
        ],
    )
    sets = SelectField(
        "Sets",
        validators=[DataRequired()],
        coerce=int,
        choices=[
            ("1", "1"),
            ("2", "2"),
            ("3", "3"),
            ("4", "4"),
            ("5", "5"),
            ("6", "6"),
        ],
    )
    reps = SelectField(
        "Reps",
        validators=[DataRequired()],
        coerce=int,
        choices=[
            ("1", "1"),
            ("2", "2"),
            ("3", "3"),
            ("4", "4"),
            ("5", "5"),
            ("6", "6"),
            ("7", "7"),
            ("8", "8"),
            ("9", "9"),
            ("10", "10"),
        ],
    )
    weight = FloatField("Load (lbs)", validators=[DataRequired()])
    rpe = SelectField(
        "RPE",
        validators=[DataRequired()],
        coerce=float,
        choices=[
            ("4", "4"),
            ("4.5", "4.5"),
            ("5", "5"),
            ("5.5", "5.5"),
            ("6", "6"),
            ("6.5", "6.5"),
            ("7", "7"),
            ("7.5", "7.5"),
            ("8", "8"),
            ("8.5", "8.5"),
            ("9", "9"),
            ("9.5", "9.5"),
            ("10", "10"),
        ],
    )
    submit = SubmitField("Log Workout")
