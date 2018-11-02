from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length

class LoginForm(FlaskForm):
    username = StringField('username')
    password = PasswordField('password')
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email',)
    username = StringField('username')
    password = PasswordField('password')

class GetForm(FlaskForm):
	key = StringField('key')

class SetForm(FlaskForm):
	key = StringField('key')
	value = StringField('value')