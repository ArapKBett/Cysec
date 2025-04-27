import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-' + secrets.token_hex(16)
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}
    SESSION_PERMANENT = False
    SESSION_TYPE = 'filesystem'
    DEBUG = False

class ProductionConfig(Config):
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True
