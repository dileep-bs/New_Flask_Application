from itsdangerous import URLSafeTimedSerializer
from simple_app import app


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        user_email = serializer.loads(token,
                                      salt=app.config['SECURITY_PASSWORD_SALT'],
                                      max_age=expiration)
        return user_email
    except Exception as e:
        print("exception in confirm_token ",e)
