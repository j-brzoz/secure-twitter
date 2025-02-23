from decouple import config
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_paranoid import Paranoid

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

from passlib.totp import TOTP
TotpFactory = TOTP.using(digits=6,alg="sha1",period=30,secrets_path=Config.SECRETS_PATH, issuer=Config.APP_NAME)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

port = '11211'
host = 'memcached'
memcached_uri = f'memcached://{host}:{port}'
limiter = Limiter(storage_uri=memcached_uri, key_func=get_remote_address)

app = Flask(__name__)
limiter.init_app(app)
paranoid = Paranoid(app)
paranoid.redirect_view = '/'
app.config.from_object(config("APP_SETTINGS"))

db.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)

from src.accounts.views import accounts_bp
from src.content.views import content_bp
from src.accounts.models import User

app.register_blueprint(accounts_bp)
app.register_blueprint(content_bp)

login_manager.login_view = "accounts.login"
login_manager.login_message_category = "danger"


@login_manager.user_loader
def load_user(user_id):
	return User.query.filter(User.id == int(user_id)).first()

