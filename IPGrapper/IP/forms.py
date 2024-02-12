from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,Email,Length,Regexp,EqualTo,ValidationError
from flask_wtf.file import FileField, FileAllowed
from IPGrapper.models import User
from flask_login import current_user


class RegistrationForm(FlaskForm):
    first_name = StringField('first name',validators=[DataRequired(),Length(min=2,max=16)])
    last_name = StringField('last name',validators=[DataRequired(),Length(min=2,max=16)])
    username = StringField('Username', validators=[
        DataRequired(message='This field is required.'),
        Length(min=4, max=32, message='Username must be between 4 and 32 characters.'),
        Regexp("^[a-z0-9_]*(?<!\\.)$"
, message='Username must not contain uppercases , special symbols or ends with "."  ')
    ])
    email = StringField('email',validators=[DataRequired(),Email()])
    password = PasswordField('password',validators=[DataRequired(),Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,24}$")])
    confirm_password = PasswordField('confirm password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('sign up')
    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('this username is taken , please choose another one')
    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('this email is taken , please choose another one')

class LoginForm(FlaskForm):
    email = StringField('email',validators=[DataRequired(),Email()])
    password = PasswordField('password',validators=[DataRequired()])
    submit = SubmitField('login')
    remember = BooleanField('remember me')
    
class Dashboard(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Email()])
    username = StringField('Username', validators=[
        DataRequired(message='This field is required.'),
        Length(min=4, max=32, message='Username must be between 4 and 32 characters.'),
        Regexp("^[a-z0-9_]+(?:\.[a-z0-9_]+)*$"
, message='Username must not contain uppercases , special symbols or ends with "."  ')
    ])
    submit = SubmitField('Update')
    def validate_email(self,email):
        if current_user.email != email.data:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('this email is taken , please choose another one')
    
    def validate_username(self,username):
        if current_user.username != username.data:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('this username is taken , please choose another one')

class RequestReset(FlaskForm):
    email = StringField('email',validators=[DataRequired(),Email()])
    submit = SubmitField('Submit')

class ResetPassword(FlaskForm):
    password = PasswordField('password',validators=[DataRequired(),Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,24}$")])
    confirm_password = PasswordField('confirm password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Change Password')
    