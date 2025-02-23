from flask_wtf import FlaskForm
from wtforms import TextAreaField
from wtforms.validators import DataRequired, Length
from flask_wtf.file import FileField, FileAllowed

class TweetForm(FlaskForm):
    text = TextAreaField("What's up?",validators=[DataRequired(),Length(min=1, max=140)])
    img = FileField('Include Image',validators=[FileAllowed(['jpg'], "Only .jpg files are allowed!")])
    private_key = FileField('Include private RSA key for signature:', validators=[FileAllowed(['pem'], "Only .pem files are allowed!")])
