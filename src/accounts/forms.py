from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, EqualTo, Length, InputRequired, Email
from src.utils import check_if_letter_or_numeric, check_if_username_exists, check_if_numeric, check_password_strength

class RegisterForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired(), Length(min=6, max=40), check_if_letter_or_numeric, check_if_username_exists])
	email = EmailField('Email address', validators=[DataRequired(), Length(max=100), Email(check_deliverability=True)]) # syntax check + DNS MX record lookup
	password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=256), check_password_strength])
	confirm = PasswordField("Repeat password", validators=[DataRequired(), EqualTo("password", message="Passwords must match."),],)
	public_key = FileField('Include public RSA key:', validators=[FileRequired(), FileAllowed(['pem'], "Only .pem files are allowed!")])

class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired(), Length(min=6, max=40), check_if_letter_or_numeric])
	password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=256)])

class TwoFactorForm(FlaskForm):
	otp = StringField('Enter OTP', validators=[InputRequired(), Length(min=6, max=6), check_if_numeric])

class ChangePasswordForm(FlaskForm):
	old_password = PasswordField("Old password", validators=[DataRequired(), Length(min=8, max=256)])
	new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8, max=256), check_password_strength])
	confirm = PasswordField("Repeat new password", validators=[DataRequired(), EqualTo("new_password", message="Passwords must match."),],)

class ForgotPasswordForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired(), Length(min=6, max=40), check_if_letter_or_numeric])
	email = EmailField('Email address', validators=[DataRequired(), Length(max=100), Email(check_deliverability=True)]) # syntax check + DNS MX record lookup
	otp = StringField('Enter OTP', validators=[InputRequired(), Length(min=6, max=6), check_if_numeric])

class SetPasswordForm(FlaskForm):
	new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8, max=256), check_password_strength])
	confirm = PasswordField("Repeat new password", validators=[DataRequired(), EqualTo("new_password", message="Passwords must match."),],)
	otp = StringField('Enter OTP', validators=[InputRequired(), Length(min=6, max=6), check_if_numeric])