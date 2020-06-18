from simple_app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),unique=True,nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60),nullable=False)
    is_active = db.Column(db.Boolean(), default=False)

    def __repr__(self):
        return f"User('{self.username}','{self.email}','{self.password}','{self.is_active}')"
