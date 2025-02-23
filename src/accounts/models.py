from datetime import datetime

from passlib.hash import argon2
from passlib.exc import TokenError, MalformedTokenError
from flask_login import UserMixin

from src import db
from src import TotpFactory

# https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
FIRST_RECOMMENDED_ARGON2 = {"type":"ID","salt_size":16,"time_cost":1,"parallelism":4,"memory_cost":1024*1024*2,"digest_size":32}

class User(UserMixin, db.Model):

	__tablename__ = "users"

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String, unique=True, nullable=False)
	email_id = db.Column(db.Integer, db.ForeignKey('emails.id'), nullable=True) 
	password = db.Column(db.String, nullable=False)
	created_at = db.Column(db.DateTime, nullable=False)
	totp = db.Column(db.String, unique=True)
	pub_key = db.Column(db.String, nullable=False)
	is_confirmed = db.Column(db.Boolean, nullable=False, default=False)
	confirmed_on = db.Column(db.DateTime, nullable=True)

	posts = db.relationship('Tweet', backref='author', lazy=True)

	def __init__(self, username, password, public_key):
		self.username = username
		self.password = argon2.using(**FIRST_RECOMMENDED_ARGON2).hash(password)
		self.created_at = datetime.now()
		self.totp = TotpFactory.new(label=self.username).to_json(encrypt=True)
		self.pub_key = public_key

	def is_otp_valid(self, user_otp):
		try:
			match = TotpFactory.verify(user_otp, self.totp, time=datetime.now(), window=30, skew=0)
		except MalformedTokenError as err:
			return False
		except TokenError as err:
			return False
		else:
			return True

	def change_password(self, new_password):
		self.password = argon2.using(**FIRST_RECOMMENDED_ARGON2).hash(new_password)

	def validate_password(self, password):
		return argon2.using(**FIRST_RECOMMENDED_ARGON2).verify(password, self.password)

	def __repr__(self):
		return f"<user {self.username}>"
	

class Email(db.Model):

	__tablename__ = "emails"

	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String, nullable=True, unique=True)

	user = db.relationship('User', backref='email', lazy=True)

	def __init__(self, email=None):
		if email:
			self.email = argon2.using(salt=b'1234567890abcdef',**FIRST_RECOMMENDED_ARGON2).hash(email)
		else:
			self.email = email

	def __repr__(self):
		return f"<email {self.id}>"
	

class Login_log(db.Model):

	__tablename__ = "login_logs"

	id = db.Column(db.Integer, primary_key=True)
	ip_address = db.Column(db.String, nullable=False)
	username = db.Column(db.String, nullable=False)
	attempt_at = db.Column(db.DateTime, nullable=False)
	is_successful = db.Column(db.Boolean, nullable=False)

	def __init__(self, ip_address, username, attempt_at, is_successful):
		self.ip_address = ip_address
		self.username = username
		self.attempt_at = attempt_at
		self.is_successful = is_successful
		print(self)

	def __repr__(self):
		return f"<{"Successful" if self.is_successful else "Unsuccessful"} attempt from {self.ip_address} at {self.attempt_at} for user: {self.username}>"
	
class TOTP_log(db.Model):

	__tablename__ = "totp_logs"

	id = db.Column(db.Integer, primary_key=True)
	ip_address = db.Column(db.String, nullable=False)
	username = db.Column(db.String, nullable=False)
	attempt_at = db.Column(db.DateTime, nullable=False)
	is_successful = db.Column(db.Boolean, nullable=False)

	def __init__(self, ip_address, username, attempt_at, is_successful):
		self.ip_address = ip_address
		self.username = username
		self.attempt_at = attempt_at
		self.is_successful = is_successful
		print(self)

	def __repr__(self):
		return f"< {"Successful" if self.is_successful else "Unsuccessful"} TOTP attempt from {self.ip_address} at {self.attempt_at} for user: {self.username}>"
