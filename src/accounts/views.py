from .forms import LoginForm, RegisterForm, TwoFactorForm, ChangePasswordForm, ForgotPasswordForm, SetPasswordForm
from src.accounts.models import User, Email, Login_log, TOTP_log
from src import db, TotpFactory, limiter
from src.utils import logout_required, generate_token, confirm_token, send_email, confirmed_required, check_attempts, scan_file, check_if_ipv4, save_log
from flask_login import current_user, login_required, login_user, logout_user
from flask import Blueprint, flash, redirect, render_template, request, url_for, session
from passlib.hash import argon2
import time
from datetime import datetime
from sqlalchemy import exc
import bleach

# https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
FIRST_RECOMMENDED_ARGON2 = {"type":"ID","salt_size":16,"time_cost":1,"parallelism":4,"memory_cost":1024*1024*2,"digest_size":32}

accounts_bp = Blueprint("accounts", __name__)
limiter.limit('10/second')(accounts_bp)

HOME_URL = "content.home"
SETUP_2FA_URL = "accounts.setup_two_factor_auth"
VERIFY_2FA_URL = "accounts.verify_two_factor_auth"
LOGIN_URL = "accounts.login"
REGISTRATION_URL = "accounts.register"
WALL_URL = "content.wall"
VERIFY_2FA_CHANGE_PASSWORD_URL = "accounts.verify_2fa_change_password"
CHANGE_PASSWORD_URL = "accounts.change_password"
FORGOT_PASSWORD_URL = "accounts.forgot_password"

@accounts_bp.route("/register", methods=["GET", "POST"])
@logout_required
def register():
	form = RegisterForm()
	if form.validate_on_submit():
		time.sleep(1)
		try:
			public_key = request.files['public_key'] if 'public_key' in request.files else None
			scan_file(public_key)
			public_key.seek(0)
			user = User(username=form.username.data, password=form.password.data, public_key=public_key.read())
			db.session.add(user)
			db.session.commit()
			session['username'] = user.username
			unique_email = False
			try:
				email = Email(form.email.data)
				db.session.add(email)
				db.session.commit()
				unique_email = True
			except exc.IntegrityError:
				db.session.rollback()

			if unique_email:
				token = generate_token(form.email.data, user.username)
				confirm_url = f"https://localhost:443/confirm/{token}"
				html = render_template("accounts/confirm_email.html", confirm_url=confirm_url)
				subject = "Please confirm your email"
				send_email(form.email.data, subject, html)
			flash("A confirmation email has been sent via email.", "success")
			return redirect(url_for(SETUP_2FA_URL))
		except Exception:
			db.session.rollback()
			flash("Invalid credentials.", "danger")

	return render_template("accounts/register.html", form=form)


@accounts_bp.route("/login", methods=["GET", "POST"])
@limiter.limit('1/second')
@logout_required
def login():
	form = LoginForm(request.form)
	if form.validate_on_submit():
		time.sleep(1)
		ip_address = request.environ['HTTP_X_FORWARDED_FOR']
		valid_address = check_if_ipv4(ip_address)
		if valid_address:
			username = form.username.data
			check_attempts(Login_log, ip_address, username)
			user = User.query.filter_by(username=username).first()
			if user and user.validate_password(request.form["password"]):
				save_log(db, Login_log, ip_address, username, True)
				session['username'] = user.username
				return redirect(url_for(VERIFY_2FA_URL))
			else:
				save_log(db, Login_log, ip_address, username, False)
		flash("Invalid credentials.", "danger")
	return render_template("accounts/login.html", form=form)

@accounts_bp.route("/logout")
@login_required
def logout():
	session.pop('username', None)
	logout_user()
	flash("You were logged out.", "success")
	return redirect(url_for("accounts.login"))
	
@accounts_bp.route("/forgot_password", methods=["GET", "POST"])
@logout_required
@limiter.limit('5/second')
def forgot_password():
	form = ForgotPasswordForm(request.form)
	if form.validate_on_submit():
		time.sleep(1)
		ip_address = request.environ['HTTP_X_FORWARDED_FOR']
		valid_address = check_if_ipv4(ip_address)
		if valid_address:
			username = form.username.data
			check_attempts(TOTP_log, ip_address, username)
			user = User.query.filter_by(username=username).first()
			if user and user.is_confirmed:
				if user.is_otp_valid(form.otp.data):
					save_log(db, TOTP_log, ip_address, username, True)
					users_email = Email.query.filter_by(id=user.email_id).first()
					if argon2.using(salt=b"1234567890abcdef", **FIRST_RECOMMENDED_ARGON2).verify(form.email.data, users_email.email):
						token = generate_token(user.username, "forgot_password")
						set_password_url = f"https://localhost:443/set-password/{token}"
						html = render_template("accounts/forgot-password-email.html", set_password_url=set_password_url)
						subject = "Password change email"
						send_email(form.email.data, subject, html)
						return redirect(url_for(LOGIN_URL))
				else:
					save_log(db, TOTP_log, ip_address, username, False)
		flash("Invalid credentials.", "danger")
		return redirect(url_for(FORGOT_PASSWORD_URL))	
	else:
		return render_template("accounts/forgot-password.html", form=form)

@accounts_bp.route("/set-password/<token>", methods=["GET", "POST"])
@logout_required
def set_password(token):
	username = confirm_token(token, "forgot_password")
	if username:
		form = SetPasswordForm(request.form)
		if form.validate_on_submit():
			time.sleep(1)
			ip_address = request.environ['HTTP_X_FORWARDED_FOR']
			valid_address = check_if_ipv4(ip_address)
			if valid_address:
				check_attempts(TOTP_log, ip_address, username)
				user = User.query.filter_by(username=username).first()
				if user and user.is_confirmed: 
					if user.is_otp_valid(form.otp.data):
						save_log(db, TOTP_log, ip_address, username, True)		
						user.change_password(form.new_password.data)
						db.session.add(user)
						db.session.commit()
						flash("Password has been changed!", "success")
						return redirect(url_for(LOGIN_URL))
					else:
						save_log(db, TOTP_log, ip_address, username, False)
			flash("Invalid credentials.", "danger")
		return render_template("accounts/set-password.html", form=form)
	else:
		flash("Invalid credentials.", "danger")
	return redirect(url_for(LOGIN_URL))
	

@accounts_bp.route("/setup-2fa")
def setup_two_factor_auth():
	if 'username' not in session:
		return redirect(url_for(REGISTRATION_URL))
	user = User.query.filter_by(username=session['username']).first()
	if user is None:
		flash("Invalid credentials.", "danger")
		return redirect(url_for(REGISTRATION_URL))
	totp = TotpFactory.from_source(user.totp)
	secret = totp.pretty_key()
	return render_template("accounts/setup-2fa.html", secret=bleach.clean(secret))

@accounts_bp.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit('1/second')
def verify_two_factor_auth():
	form = TwoFactorForm(request.form)
	
	if 'username' not in session:
		return redirect(url_for(LOGIN_URL))
	
	user = User.query.filter_by(username=session['username']).first()
	if user is None:
		flash("Invalid credentials.", "danger")
		return redirect(url_for(LOGIN_URL))
	
	if form.validate_on_submit():
		time.sleep(1)
		ip_address = request.environ['HTTP_X_FORWARDED_FOR']
		valid_address = check_if_ipv4(ip_address)
		if valid_address:
			check_attempts(TOTP_log, ip_address, user.username)
			if user and user.is_otp_valid(form.otp.data):
				save_log(db, TOTP_log, ip_address, user.username, True)
				login_user(user)
				flash("2FA verification successful. You are logged in!", "success")
				return redirect(url_for(WALL_URL))
			else:
				save_log(db, TOTP_log, ip_address, user.username, False)
		flash("Invalid credentials.", "danger")
	return render_template("accounts/verify-2fa.html", form=form)

@accounts_bp.route("/verify_2fa_change_password", methods=["GET", "POST"])
@login_required
@confirmed_required
@limiter.limit('5/second')
def verify_2fa_change_password():
	form = TwoFactorForm(request.form)
	if form.validate_on_submit():
		time.sleep(1)
		ip_address=request.environ['HTTP_X_FORWARDED_FOR']
		valid_address = check_if_ipv4(ip_address)
		if valid_address:
			check_attempts(TOTP_log, ip_address, current_user.username)

			if current_user and current_user.is_otp_valid(form.otp.data):
				save_log(db, TOTP_log, ip_address, current_user.username, True)
				session['username_change_password'] = current_user.username
				flash("2FA verification successful!", "success")
				return redirect(url_for(CHANGE_PASSWORD_URL))
			else:
				save_log(db, TOTP_log, ip_address, current_user.username, False)
		flash("Invalid credentials.", "danger")
		return redirect(url_for(VERIFY_2FA_CHANGE_PASSWORD_URL))
	else:
		return render_template("accounts/verify-2fa.html", form=form)
		
@accounts_bp.route("/change_password", methods=["GET", "POST"])
@login_required
@confirmed_required
@limiter.limit('1/second')
def change_password():
	form = ChangePasswordForm(request.form)

	if 'username_change_password' not in session:
		return redirect(url_for(VERIFY_2FA_CHANGE_PASSWORD_URL))
	user = User.query.filter_by(username=session['username_change_password']).first()
	if user is None or user.username != current_user.username:
		session.pop('username_change_password', None)
		flash("Invalid credentials.", "danger")
		return redirect(url_for(VERIFY_2FA_CHANGE_PASSWORD_URL))
	
	if form.validate_on_submit():
		time.sleep(1)
		if current_user.validate_password(request.form["old_password"]):
			session.pop('username_change_password', None)
			current_user.password = argon2.using(**FIRST_RECOMMENDED_ARGON2).hash(request.form["new_password"])
			db.session.commit()
			flash('Password changed', "success")
			return redirect(url_for(WALL_URL))
		else:
			session.pop('username_change_password', None)
			flash("Invalid credentials.", "danger")
			return redirect(url_for(WALL_URL))
	else:
		return render_template("accounts/change-password.html", form=form)

@accounts_bp.route("/confirm/<token>")
@login_required
def confirm_email(token):
	if current_user.is_confirmed:
		flash("Account already confirmed.", "success")
		return redirect(url_for(WALL_URL))
	email = confirm_token(token, current_user.username)
	if email:
		user = User.query.filter_by(username=current_user.username).first()
		email_in_db = Email.query.filter_by(email=argon2.using(salt=b"1234567890abcdef", **FIRST_RECOMMENDED_ARGON2).hash(email)).first()
		user.is_confirmed = True
		user.confirmed_on = datetime.now()
		user.email_id = email_in_db.id
		db.session.add(user)
		db.session.commit()
		flash("You have confirmed your account. Thanks!", "success")
	else:
		flash("Invalid credentials.", "danger")
	return redirect(url_for(WALL_URL))

@accounts_bp.route("/not-confirmed")
@login_required
def not_confirmed():
    if current_user.is_confirmed:
        return redirect(url_for(WALL_URL))
    return render_template("accounts/not-confirmed.html")