from base64 import b64encode
from src.accounts.models import User
from wtforms.validators import ValidationError
import unicodedata
import zxcvbn
from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user
from config import Config
from itsdangerous import URLSafeTimedSerializer
import time
from datetime import datetime, timedelta
import pyclamd
import ipaddress


def check_if_username_exists(form, field):
	user = User.query.filter_by(username=field.data).first()	
	if user:
		raise ValidationError('Username already taken!')
	
def check_if_letter_or_numeric(form, field):
	char_categories = [unicodedata.category(c)[0] for c in field.data]
	if any([cat not in ["L", "N"] for cat in char_categories]):
		raise ValidationError('Username can only contain letters and numbers!')
	
def check_if_numeric(form, field):
	char_categories = [unicodedata.category(c)[0] for c in field.data]
	if any([cat not in ["N"] for cat in char_categories]):
		raise ValidationError('OTP can only contain letters and numbers!')

def check_password_strength(form, field):
	results = zxcvbn.zxcvbn(field.data)
	if results["score"] < 3:
		# 0  too guessable: risky password. (guesses < 10^3)
		# 1  very guessable: protection from throttled online attacks. (guesses < 10^6)
		# 2  somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)
		# 3  safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)
		# 4  very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
		raise ValidationError(results["feedback"]["warning"])
	
def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already authenticated.", "info")
            return redirect(url_for("content.wall"))
        return func(*args, **kwargs)
    return decorated_function

def confirmed_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_confirmed is False:
            flash("Please confirm your account!", "warning")
            return redirect(url_for("accounts.not_confirmed"))
        return func(*args, **kwargs)

    return decorated_function

def generate_token(email, salt):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    return serializer.dumps(email, salt=salt)

def confirm_token(token, salt, expiration=3600):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    try:
        email = serializer.loads(token, salt=salt, max_age=expiration)
        return email
    except Exception:
        return False

def send_email(to, subject, html):
	header = f"Send '{subject}' from noreply@safespace.com to:{to}\n"
	print(header+html)
      
def check_attempts(log, ip_address, username):
	current_time = datetime.now()
	attempts = log.query.filter(
		log.attempt_at >= current_time - timedelta(minutes=1),
		log.attempt_at <= current_time,
		log.is_successful == False,
		log.ip_address == ip_address,
		log.username == username
	).count()
	
	if attempts >= 2:
		time.sleep(10)
	else:
		flash("3 wrong attempts -> 10s. timeout", "danger")

def scan_file(file):
	cd = pyclamd.ClamdAgnostic()
	scan_result = cd.scan_stream(file.read())
	if scan_result:
		raise Exception("Malware detected!")
			
def check_if_ipv4(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False
    
def save_log(db, type, ip_address, username, is_successful):
	log = type(ip_address=ip_address, username=username, attempt_at=datetime.now(), is_successful=is_successful)
	db.session.add(log)
	db.session.commit()