import os
import secrets
from datetime import timedelta
from pathlib import Path

class Config:
    """Base configuration with security hardening"""
    # Core Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(64)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_urlsafe(64)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    }

    # File Upload Security
    UPLOAD_FOLDER = Path('uploads')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS = {
        'documents': {'txt', 'pdf', 'docx', 'doc', 'rtf'},
        'images': {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg'},
        'archives': {'zip', 'tar', 'gz', 'rar', '7z'},
        'executables': {'exe', 'dll', 'so', 'bin'},
        'scripts': {'py', 'js', 'html', 'css', 'xml', 'json'}
    }

    # Database Configuration - with fallback to SQLite
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL:
        # Fix postgres:// to postgresql:// for SQLAlchemy 2.0
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        SQLALCHEMY_DATABASE_URI = 'sqlite:///cybersec.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_SIZE = 20
    SQLALCHEMY_POOL_TIMEOUT = 30

    # Redis Configuration - with fallback
    REDIS_URL = os.environ.get('REDIS_URL')
    if REDIS_URL:
        CACHE_TYPE = 'redis'
        CACHE_REDIS_URL = REDIS_URL
        RATELIMIT_STORAGE_URL = REDIS_URL
    else:
        CACHE_TYPE = 'simple'  # In-memory fallback
        CACHE_REDIS_URL = None
        RATELIMIT_STORAGE_URL = None

    CACHE_DEFAULT_TIMEOUT = 300

    # Rate Limiting
    RATELIMIT_DEFAULT = "1000 per hour"
    RATELIMIT_HEADERS_ENABLED = True

    # Session Configuration
    SESSION_TYPE = 'redis'
    SESSION_REDIS = REDIS_URL
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'cybersec:'

    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    STRUCTURED_LOGGING = True

    # API Configuration
    API_VERSION = 'v2'
    API_TITLE = 'CyberSec Professional Suite'
    API_DESCRIPTION = 'Enterprise Cybersecurity Toolkit API'

    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
    CENSYS_API_ID = os.environ.get('CENSYS_API_ID')
    CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET')
    GREYNOISE_API_KEY = os.environ.get('GREYNOISE_API_KEY')

    # Scanning Configuration
    MAX_SCAN_THREADS = int(os.environ.get('MAX_SCAN_THREADS', '500'))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '10'))
    MAX_PORT_RANGE = int(os.environ.get('MAX_PORT_RANGE', '65535'))

    # YARA Rules
    YARA_RULES_PATH = Path('rules/yara')
    CUSTOM_YARA_RULES_PATH = Path('rules/custom')

    # Wordlists
    WORDLIST_PATH = Path('wordlists')
    PASSWORD_LISTS_PATH = Path('wordlists/passwords')

    # ML Models
    MODEL_PATH = Path('models')
    THREAT_DETECTION_MODEL = 'threat_classifier.pkl'

    # Elasticsearch Configuration
    ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL')
    ELASTICSEARCH_INDEX_PREFIX = 'cybersec'

    # Monitoring
    PROMETHEUS_METRICS_PATH = '/metrics'
    HEALTH_CHECK_PATH = '/health'

    # Features Flags
    ENABLE_ADVANCED_SCANNING = True
    ENABLE_THREAT_INTELLIGENCE = True
    ENABLE_ML_ANALYSIS = True
    ENABLE_OSINT_TOOLS = True
    ENABLE_VULNERABILITY_SCANNING = True
    ENABLE_REAL_TIME_MONITORING = True

class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    TESTING = False
    WTF_CSRF_ENABLED = False
    LOG_LEVEL = 'DEBUG'

class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    TESTING = False

    # Enhanced Security for Production
    SSL_REQUIRE = True
    FORCE_HTTPS = True
    HSTS_MAX_AGE = 31536000

    # Performance Optimization
    SQLALCHEMY_POOL_SIZE = 50
    SQLALCHEMY_POOL_TIMEOUT = 60
    CACHE_DEFAULT_TIMEOUT = 600

    # Monitoring
    APM_ENABLED = True
    METRICS_ENABLED = True

class EnterpriseConfig(ProductionConfig):
    """Enterprise environment with additional features"""

    # Advanced Security
    MULTI_FACTOR_AUTHENTICATION = True
    AUDIT_LOGGING = True
    ENCRYPTION_AT_REST = True

    # Compliance
    SOC2_COMPLIANCE = True
    GDPR_COMPLIANCE = True
    HIPAA_COMPLIANCE = True

    # Enterprise Features
    LDAP_INTEGRATION = True
    SSO_ENABLED = True
    RBAC_ENABLED = True

    # High Availability
    CLUSTER_MODE = True
    AUTO_SCALING = True
    FAILOVER_ENABLED = True

# Configuration mapping
config_map = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'enterprise': EnterpriseConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'default')
    return config_map.get(env, DevelopmentConfig)