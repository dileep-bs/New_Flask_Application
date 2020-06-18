from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired,Length,Email,EqualTo
from wtforms.validators import InputRequired,Length,AnyOf


class RegistrationForm(FlaskForm):
    username= StringField('username',
                          validators=[DataRequired(),Length(min=2,max=20)])
    email=StringField('email',
                      validators=[DataRequired(),Email()])
    password = PasswordField('password',
                             validators=[DataRequired()])
    confirm_password = PasswordField('confirm_password',
                                     validators=[DataRequired(),EqualTo('password',message='Passwords must match')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('email',
                        validators=[DataRequired(),Email()])
    password = PasswordField('password',
                             validators=[DataRequired()])
    submit = SubmitField('Login')


class ForgotPasswordForm(FlaskForm):
    email = StringField('email',validators=[InputRequired('email is required!')])
    submit = SubmitField("Submit")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("password",
                             validators=[InputRequired('password is required!')])
    confirm_password = PasswordField("confirm_password",
                                     validators=[InputRequired('password is required!'),
                                                                    EqualTo('password',message='Passwords must match')])
    submit = SubmitField("Submit")