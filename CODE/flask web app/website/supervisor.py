from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_wtf import FlaskForm
from flask_login import current_user, login_required
from wtforms import StringField, SubmitField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length
from wtforms_sqlalchemy.fields import QuerySelectField
from flask_mail import Message
from wtforms.fields import SelectMultipleField

from .models import User
from .__init__ import db, mail


# Define the blueprint: 'supervisor', set
supervisor = Blueprint('supervisor', __name__)


# Define the Task and assign form
class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    assignee = QuerySelectField(query_factory=lambda: User.query.all(), get_label="first_name")
    priority = SelectField('Priority', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    submit = SubmitField('Submit')

class UpdateTaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    assignee = QuerySelectField(query_factory=lambda: User.query.all(), get_label="first_name")
    priority = SelectField('Priority', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    submit = SubmitField('Update')
    
class TaskAssignForm(FlaskForm):
    task_id = StringField('Task ID', validators=[DataRequired()])
    assignees = SelectMultipleField('Assignees', coerce=int)
    submit = SubmitField('Assign')

    class EmailNotification:
        @staticmethod
        def send_notification(user_email, task_title):
            msg = Message('Task Assignment', recipients=[user_email])
            msg.body = f"You have been assigned a new task: {task_title}"
            mail.send(msg)

