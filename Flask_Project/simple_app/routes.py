from flask import render_template, flash, redirect, url_for, request,session
from simple_app import app,db,bcrypt
from simple_app.forms import RegistrationForm,LoginForm,ForgotPasswordForm,ResetPasswordForm
from simple_app.models import User
from flask.views import View
from flask import Flask, jsonify, request
from flask_restful import Resource, Api,reqparse
from flask import render_template, make_response
from os import environ
from flask_mail import Message,Mail
from .Token import generate_confirmation_token,confirm_token
from .Exceptions import TokenExpired,DataNotSufficient,InvalidCredencials
from itsdangerous import URLSafeTimedSerializer,SignatureExpired

EMAIL_HOST_USER = environ.get('EMAIL_HOST_USER')
PASSWORD = environ.get('EMAIL_HOST_PASSWORD')

app.config['SECRET_KEY'] = '4b70b5e6a77a9807c7e0'
app.config['SECURITY_PASSWORD_SALT'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:new_password@localhost/site'
app.config['MAIL_USERNAME'] = EMAIL_HOST_USER
app.config['MAIL_PASSWORD'] = PASSWORD


app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = EMAIL_HOST_USER,
    MAIL_PASSWORD = PASSWORD,
))

api=Api(app)
mail = Mail(app)
app = Flask(__name__)
mail.init_app(app)

EMAIL_HOST_USER = environ.get('EMAIL_HOST_USER')
PASSWORD = environ.get('EMAIL_HOST_PASSWORD')
print(EMAIL_HOST_USER)

parser = reqparse.RequestParser()

class ShowHelloWorld(Resource):
    def get(self):
        return jsonify({'message':'Hello World!'})
api.add_resource(ShowHelloWorld, '/hello_word')

class Home(Resource):
    def get(self):
        return make_response(render_template('index.html'))
api.add_resource(Home, '/home')

class Welcome_page(Resource):
    def get(self):
        return jsonify({'message': 'welcome_page'})
api.add_resource(Welcome_page, '/welcome_page')

class Register(Resource):
    """
    Summary:
    --------
    Register class allows user to get register into form.
        
    Methods:
    --------
    post: post the user data send into database.
    get: get the token from email and confirm email.
    """
    def post(self):
        try:
            form = RegistrationForm()
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=hashed_password)
            user_exist = User.query.filter_by(email=email).first()
            if user_exist:
                return jsonify({'message': 'user is already present in a database'})
            db.session.add(user)
            db.session.commit()
            token = generate_confirmation_token(email)
            subject = "Please confirm your email"
            msg = Message(subject=subject, sender=EMAIL_HOST_USER, recipients=[email])
            link = url_for('token', token=token, _external=True)
            print(link)
            parser.add_argument('token', type=str)
            msg.body = render_template("activate.html", link=link, email=email)
            mail.send(msg)
            return jsonify({'message': 'registration done successfully,please activate account through mailed link'})
        except DataNotSufficient:
            return jsonify({'message': 'user not given all data'})

    def get(self,token):
        try:
            user_email = confirm_token(token)
            user = User.query.filter_by(email=user_email).first()
            user.is_active = True
            db.session.add(user)
            db.session.commit()
            return jsonify({'message': 'Your account activated successfully,please login'})
        except TokenExpired:
            return jsonify({'message': 'Your token missing'})
api.add_resource(Register,  '/register')
api.add_resource(Register,'/register/<string:token>', endpoint='token')

class Forgot_password(Resource):
    """
    Summary:
    --------
    Forgot_password class allows user to reset the password of his account.

    Methods:
    --------
    post: post the user data to confirm the account and generate token link.
    put: get the token from email and reset password by confirm the token.
    """
    def post(self):
        try:
            form = ForgotPasswordForm()
            email = request.form.get("email")
            user_exist = User.query.filter_by(email=email).first()
            if user_exist:
                token = generate_confirmation_token(email)
                subject = "Please confirm your email"
                msg = Message(subject=subject, sender=EMAIL_HOST_USER, recipients=[email])
                link = url_for('reset_token', token=token, _external=True)
                msg.body = render_template("forgotpassword.html",link=link,email=email)
                mail.send(msg)
                return jsonify({'message':"Email was sent successfully to your account"})
            return jsonify({'message': 'SORRY!... user is not present in a database'})

        except DataNotSufficient :
            return jsonify({'message': 'user not given all data'})

    def put(self,token):
        try:
            form = ResetPasswordForm()
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")
            user_email = confirm_token(token)
            user = User.query.filter_by(email=user_email).first()
            if password!=confirm_password:
                return jsonify({'message': 'Enter password properly'})
            if user:
                hashed_password = bcrypt.generate_password_hash(confirm_password).decode('utf-8')
                user = User.query.filter_by(username=user.username).first()
                user.password = hashed_password
                db.session.add(user)
                db.session.commit()
                return jsonify({'message': 'Your rest password successfully done,please login'})
            else:
                return jsonify({'message': 'Entered password is not same'})
        except TokenExpired :
            return jsonify({'message': 'Your token missing'})
api.add_resource(Forgot_password,'/forgotpassword')
api.add_resource(Forgot_password,'/forgotpassword/<string:token>', endpoint='reset_token')


class Login(Resource):
    """
    Summary:
    --------
    Login class allows user to login into the session.

    Methods:
    --------
    post: post the user data to databases with login credentials.
    """
    def post(self):
        try:
            form = LoginForm()
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if not user or not bcrypt.check_password_hash(user.password, password):
                flash('Please check your login details and try again.')
                return jsonify({'message': 'Invalid credentials '})
            if user.is_active:
                session['username'] = user.username
                session["email"] = user.email
                flash('login successfully')
                return jsonify({'message': 'User login successfully'})
            else:
                return jsonify({'message': 'Check ur mail and confirm the email'})
        except InvalidCredencials :
            return jsonify({'message': 'user not given all data'})
api.add_resource(Login, '/login')


class Logout(Resource):
    """
    Summary:
    --------
    Logout class allows user to logout from the session.

    Methods:
    --------
    post: post method allows to logout.
    """
    def post(self):
        try:
            session.clear()
            return jsonify({'message': "logout successfully done"})
        except Exception:
            return jsonify({'message': 'something went wrong'})
api.add_resource(Logout, '/logout')