from decouple import config
import os

DATABASE_URI = config("DATABASE_URL")

class Config(object):
	DEBUG = False
	TESTING = False
	CSRF_ENABLED = True
	SECRET_KEY = config("SECRET_KEY")
	SQLALCHEMY_DATABASE_URI = DATABASE_URI
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	WTF_CSRF_ENABLED = True
	DEBUG_TB_ENABLED = False
	DEBUG_TB_INTERCEPT_REDIRECTS = False
	APP_NAME = config("APP_NAME")
	UPLOAD_FOLDER = os.path.join('static', 'uploads')
	MAX_CONTENT_LENGTH = 16 * 1024 * 1024 # 16 MB
	SECRETS_PATH='secrets'
	SESSION_COOKIE_SECURE = True
	REMEMBER_COOKIE_SECURE = True


class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///testdb.sqlite"


class ProductionConfig(Config):
    DEBUG = False
    DEBUG_TB_ENABLED = False