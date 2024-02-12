from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail


app = Flask(__name__)
app.config['SECRET_KEY'] = "zTCaZ7VKdgcHwiRDs54dLq45hFiSeh0NExJcFyPxW3Q"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= True
app.config['MAIL_SERVER']= 'smtp.googlemail.com'
app.config['MAIL_PORT']= 587
app.config['MAIL_USE_TLS']= True
app.config['MAIL_USERNAME']= 'gashehteam@gmail.com'
app.config['MAIL_PASSWORD']= 'ceys fkoa zehq aoqh'
app.config["UPLOAD_FOLDER"] = "uploads"


db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = 'info'

from IPGrapper import routes