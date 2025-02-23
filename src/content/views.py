from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from .forms import TweetForm
from .models import Tweet
from ..accounts.models import User
from src import db, limiter
from src.utils import confirmed_required
from sqlalchemy import desc
import bleach
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA512
from src.utils import scan_file

content_bp = Blueprint("content", __name__)
limiter.limit('10/second')(content_bp)

# bleach.sanitizer.ALLOWED_TAGS = frozenset({'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul'})
# bleach.sanitizer.ALLOWED_ATTRIBUTES = {'a': ['href', 'title'], 'abbr': ['title'], 'acronym': ['title']}

WALL_URL = "content.wall"

@content_bp.route("/wall", methods=["GET", "POST"])
@login_required
@confirmed_required
def wall():
	form = TweetForm(request.form)
	if form.validate_on_submit():
		try:
			img = request.files['img'] if 'img' in request.files else None
			is_signed = False
			signature = None
			hashed_value = None
			try:
				private_key = request.files['private_key'] if 'private_key' in request.files else None
				scan_file(private_key)
				private_key.seek(0)
				priv_key = RSA.import_key(private_key.read())
				pub_key = RSA.import_key(current_user.pub_key)

				h = SHA512.new(str.encode(form.text.data))
				signature = pss.new(priv_key).sign(h)

				verifier = pss.new(pub_key)
				verifier.verify(h, signature)

				signature = signature.hex()
				hashed_value = str.encode(form.text.data).hex()
				is_signed = True
			except:
				is_signed = False

			tweet = Tweet(text=form.text.data, user_id=current_user.id, img=img, is_signed=is_signed, signature=signature, hashed_value=hashed_value)
			db.session.add(tweet)
			db.session.commit()

			flash("Your thought has been shared!", "success")
			return redirect(url_for(WALL_URL))
		except Exception:
			db.session.rollback()
			flash("Sharing failed. Please try again", "danger")

	page = request.args.get(key='page', default=1, type=int)
	tweets = Tweet.query.order_by(desc(Tweet.created_at)).paginate(page=page,per_page=12)
	for tweet in tweets.items:
		tweet.text = bleach.clean(tweet.text)
		tweet.author.username = bleach.clean(tweet.author.username)
		if tweet.hashed_value: tweet.hashed_value = bleach.clean(tweet.hashed_value)
		if tweet.signature: tweet.signature = bleach.clean(tweet.signature)
	username = bleach.clean(current_user.username)
	return render_template('content/wall.html', name=username, form=form, tweets=tweets)

@content_bp.route("/view_profile/<int:user_id>", methods=["GET", "POST"])
@login_required
@confirmed_required
def view_profile(user_id):
	user = User.query.filter_by(id=user_id).first()
	page = request.args.get('page', 1, type=int)
	user_tweets = Tweet.query.filter_by(user_id=user.id).order_by(desc(Tweet.created_at)).paginate(page=page,per_page=12)
	for tweet in user_tweets.items:
		tweet.text = bleach.clean(tweet.text)
		tweet.author.username = bleach.clean(tweet.author.username)
		if tweet.hashed_value: tweet.hashed_value = bleach.clean(tweet.hashed_value)
		if tweet.signature: tweet.signature = bleach.clean(tweet.signature)
	user.username = bleach.clean(user.username)
	user.pub_key = bleach.clean(user.pub_key.hex())
	return render_template('content/view_profile.html',user=user, tweets=user_tweets)

@content_bp.route("/")
@login_required
def home():
    return redirect(url_for(WALL_URL))