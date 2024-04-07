from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from wtforms_sqlalchemy.fields import QuerySelectField  # Import QuerySelectField from wtforms.ext.sqlalchemy
from .models import Role
# Define the blueprint: 'admin', set
admin = Blueprint('admin', __name__)
#notify admin if any new user signs 
# Define the Role  and assign form
class RoleForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit')

class UserAssignForm(FlaskForm):
    role = QuerySelectField(query_factory=lambda: Role.query.all(), get_label="name")
    submit = SubmitField('Submit')

