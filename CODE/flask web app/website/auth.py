
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from .__init__ import db
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo



#Define the blueprint: 'website', set its url prefix: app.url/website
auth = Blueprint('auth', __name__)


# Define the User registration form
class RegistrationForm(FlaskForm):
    """
    Form for users to create new account
    """
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    staffNO = StringField('Staff Number', validators=[DataRequired()])
    rank = StringField('Rank', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email is already in use')

    def validate_condition(self, first_name, last_name, rank):
        if first_name == rank or last_name == rank:
            raise ValidationError('First Name, Last Name and Rank must be different')
        elif len(first_name) < 2:
            raise ValidationError('First Name is too short')
        elif len(last_name) < 2:
            raise ValidationError('Last Name is too short')
        elif len(rank) < 2:
            raise ValidationError('Rank is too short')
        
    def validate_password(self, field):
        if self.password.data != self.confirm_password.data:
            raise ValidationError('Passwords do not match')
        
class LoginForm(FlaskForm):
    """
    Form for users to login
    """
    login_id = StringField('Email or Staff Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PasswordResetRequestForm(FlaskForm):
    """
    Form for users to request a password reset
    """
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')



