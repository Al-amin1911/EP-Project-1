from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user

from .__init__ import db
#Define the blueprint: 'home', set
home = Blueprint('home', __name__)


