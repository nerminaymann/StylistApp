from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from os import path


db=SQLAlchemy()
def createapp():
    #initializing the app
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    db.init_app(app)
    login_manager = LoginManager(app)
    login_manager.login_view = '/'
    login_manager.init_app(app)

    #making the routes
    from .views import views
    app.register_blueprint(views,url_prefix='/')

    from .models import Users
    createdatabase(app)

    @login_manager.user_loader
    def userloader(id):
        return Users.query.filter_by(id=int(id)).first()
    #returning the app
    return app
def createdatabase(app):
    if not path.exists("application/database.db"):
        db.create_all(app=app)
        print("Created")
