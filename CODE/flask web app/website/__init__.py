from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

from flask_mail import Mail
from flask_bootstrap import Bootstrap

db = SQLAlchemy()
DB_NAME = "database.db"
SECRET_KEY = 'mysecretkey'

mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config["SQLALCHEMY_ECHO"] = True
    app.config["SQLALCHEMY_RECORD_QUERIES"] = True

   
    mail.init_app(app)
    Bootstrap(app)
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_message = "Unauthorized User. Please Login."
    login_manager.login_view = 'auth.login'

    # Registering Blueprints   
    from .views import views
    from .auth import auth 
    from .supervisor import supervisor 
    from .home import home 
    from .admin import admin 
        

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(supervisor, url_prefix='/')
    app.register_blueprint(home, url_prefix='/')
    app.register_blueprint(admin, url_prefix='/admin')

    from .models import User

    with app.app_context():
        # Import models and create database
        db.create_all

        # User loader
        @login_manager.user_loader
        def load_user(id):
            return User.query.get(int(id))
            
        # Error handlers
        @app.errorhandler(403)
        def forbidden(e):
            return render_template('errors/403.html'), 403
            
        @app.errorhandler(404)
        def page_not_found(e):
            return render_template('errors/404.html'), 404
            
        @app.errorhandler(500)
        def server_error(e):
            return render_template('errors/500.html'), 500

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        with app.app_context():
            db.create_all()
    print("Database Created")