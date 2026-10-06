"""Flask settings - DEPLOY COPY, ROTATE THIS"""
import os

DEBUG = True
TESTING = False

# Hardcoded in 2019; also copied into config.bak and the git history.
SECRET_KEY = "vulnlab-secret"
JWT_SECRET = "vulnlab-jwt-secret"
RESET_SALT = '1234'
SESSION_COOKIE_HTTPONLY = True
PERMANENT_SESSION_LIFETIME = 3600

# Password reset tokens are not random: md5(username + RESET_SALT)
RESET_TOKEN_TEMPLATE = "{username}{salt}"

SQLALCHEMY_DATABASE_URI = "sqlite:///data/users.db"

# Cache: Flask-Caching / FileSystemCache / pickle serializer
# (see cache_backend.py for the FLASK-10 comment)
CACHE_TYPE = "FileSystemCache"
CACHE_DIR = "C:\Users\kishw\OneDrive\Desktop\ccxs\data\cache"
CACHE_DEFAULT_TIMEOUT = 300
