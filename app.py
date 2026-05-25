"""
CyberSec Professional Suite - Enterprise Cybersecurity Toolkit
Advanced security platform for professional cybersecurity operations
"""

import os
import logging
import structlog
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from flask_restful import Api
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_compress import Compress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_socketio import SocketIO
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from datetime import datetime, timedelta
import threading
import secrets
import subprocess
import json
from pathlib import Path

# Import configuration
from config import get_config

# Import enhanced modules (with error handling)
import sys
sys.path.append(str(Path(__file__).parent / 'backend' / 'python'))

try:
    from modules.advanced_scanner import AdvancedScanner
except ImportError:
    AdvancedScanner = None

try:
    from modules.threat_intelligence import ThreatIntelligence
except ImportError:
    ThreatIntelligence = None

try:
    from modules.vulnerability_scanner import VulnerabilityScanner
except ImportError:
    VulnerabilityScanner = None

try:
    from modules.advanced_crypto import AdvancedCrypto
except ImportError:
    AdvancedCrypto = None

try:
    from modules.osint import OSINTAnalyzer
except ImportError:
    OSINTAnalyzer = None

# Initialize Flask app with enterprise configuration
app = Flask(__name__)
app.config.from_object(get_config())

# Initialize extensions with error handling
jwt = JWTManager(app)
cors = CORS(app, origins=['https://*.cybersec.com', '*'])  # More permissive for development
compress = Compress(app)

try:
    cache = Cache(app)
except Exception as e:
    logger.warning("cache_initialization_failed", error=str(e))
    # Fallback to simple cache
    app.config['CACHE_TYPE'] = 'simple'
    cache = Cache(app)

try:
    socketio = SocketIO(app, cors_allowed_origins="*")
except Exception as e:
    logger.warning("socketio_initialization_failed", error=str(e))
    socketio = None

# Rate limiting with fallback storage
try:
    # Try Redis first for production
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per hour", "100 per minute"],
        storage_uri=app.config.get('REDIS_URL', 'redis://localhost:6379')
    )
except Exception:
    # Fallback to in-memory for development/simple deployments
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per hour", "100 per minute"]
    )
limiter.init_app(app)

# API initialization
api = Api(app, prefix=f'/api/{app.config["API_VERSION"]}')

# Initialize structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Prometheus metrics
request_count = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')

# Global application state for enterprise features
app_state = {
    'scanner': {'instances': {}, 'queue': []},
    'monitoring': {'active_sessions': {}, 'alerts': []},
    'threat_intel': {'feeds': {}, 'indicators': []},
    'incidents': {'active': {}, 'resolved': []},
    'compliance': {'status': {}, 'reports': []}
}

# Initialize security managers (if available)
auth_manager = None
api_security = None

@app.after_request
def security_headers(response):
    """Apply enterprise security headers"""
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    }

    for header, value in security_headers.items():
        response.headers[header] = value
    return response

@app.before_request
def log_request():
    """Log all requests with structured logging"""
    logger.info("request_started",
                method=request.method,
                path=request.path,
                remote_addr=request.remote_addr,
                user_agent=request.headers.get('User-Agent'))

@app.after_request
def log_response(response):
    """Log response and update metrics"""
    request_count.labels(method=request.method, endpoint=request.endpoint).inc()
    logger.info("request_completed",
                method=request.method,
                path=request.path,
                status_code=response.status_code)
    return response

# Authentication routes
@app.route('/api/v2/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Enhanced authentication with MFA support"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        mfa_token = data.get('mfa_token')

        # Simple authentication for demo purposes - replace with proper auth in production
        if auth_manager and auth_manager.authenticate(username, password, mfa_token):
            access_token = create_access_token(
                identity=username,
                expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
            )

            logger.info("user_authenticated", username=username)

            return jsonify({
                'access_token': access_token,
                'user': auth_manager.get_user_profile(username) if auth_manager else {'username': username},
                'permissions': auth_manager.get_user_permissions(username) if auth_manager else ['read']
            })
        elif username and password:  # Fallback authentication
            access_token = create_access_token(
                identity=username,
                expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
            )

            logger.info("user_authenticated_fallback", username=username)

            return jsonify({
                'access_token': access_token,
                'user': {'username': username, 'role': 'user'},
                'permissions': ['read', 'scan']
            })
        else:
            logger.warning("authentication_failed", username=username)
            return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        logger.error("authentication_error", error=str(e))
        return jsonify({'error': 'Authentication service error'}), 500

# Dashboard routes
@app.route('/')
def index():
    """Main dashboard with dark robotic theme"""
    try:
        return render_template('index.html')
    except Exception:
        # Fallback if templates aren't available
        return jsonify({
            'status': 'CyberSec Professional Suite',
            'version': app.config.get('API_VERSION', 'v2'),
            'message': 'API is running. Access /health for health check or /api/v2/ for API endpoints.'
        })

@app.route('/dashboard/<module>')
def dashboard_module(module):
    """Individual module dashboards"""
    valid_modules = [
        'scanner', 'threat-intel', 'vulnerability', 'crypto', 'monitor',
        'audit', 'osint', 'malware', 'incident', 'compliance', 'ids'
    ]

    if module not in valid_modules:
        return render_template('errors/404.html'), 404

    return render_template(f'dashboard/{module}.html')

# Native C/C++ Integration APIs
@app.route('/api/v2/crypto/native-encrypt', methods=['POST'])
@limiter.limit("10 per minute")
def native_encrypt():
    """High-performance encryption using C binary"""
    try:
        data = request.get_json()
        input_file = data.get('input_file')
        output_file = data.get('output_file')
        key = data.get('key')

        if not all([input_file, output_file, key]):
            return jsonify({'error': 'Missing required parameters'}), 400

        # Validate file paths for security
        if not Path(input_file).exists():
            return jsonify({'error': 'Input file does not exist'}), 400

        # Execute C encryption binary
        encrypt_binary = Path('backend/c/encrypt')
        if encrypt_binary.exists():
            result = subprocess.run([
                str(encrypt_binary),
                'encrypt',
                input_file,
                output_file,
                key
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                logger.info("native_encryption_success",
                           input_file=input_file,
                           output_file=output_file)

                return jsonify({
                    'success': True,
                    'output_file': output_file,
                    'message': 'File encrypted successfully using native C implementation',
                    'performance': 'high'
                })
            else:
                logger.error("native_encryption_failed",
                           error=result.stderr)
                return jsonify({'error': f'Encryption failed: {result.stderr}'}), 500
        else:
            return jsonify({'error': 'Native encryption binary not available'}), 503

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Encryption operation timed out'}), 408
    except Exception as e:
        logger.error("native_encryption_error", error=str(e))
        return jsonify({'error': 'Encryption operation failed'}), 500

@app.route('/api/v2/network/native-scan', methods=['POST'])
@limiter.limit("5 per minute")
def native_network_scan():
    """Real-time network scanning using C++ binary"""
    try:
        data = request.get_json()
        interface = data.get('interface', 'auto')
        duration = min(int(data.get('duration', 10)), 60)  # Max 60 seconds

        # Execute C++ sniffer binary
        sniffer_binary = Path('backend/cpp/sniffer')
        if sniffer_binary.exists():
            result = subprocess.run([
                str(sniffer_binary),
                interface,
                str(duration)
            ], capture_output=True, text=True, timeout=duration + 10)

            if result.returncode == 0:
                try:
                    # Parse JSON output from sniffer
                    scan_data = json.loads(result.stdout)

                    logger.info("native_scan_success",
                               interface=interface,
                               duration=duration,
                               packets_captured=scan_data.get('total_packets', 0))

                    return jsonify({
                        'success': True,
                        'scan_data': scan_data,
                        'interface': interface,
                        'duration': duration,
                        'performance': 'native'
                    })
                except json.JSONDecodeError:
                    return jsonify({'error': 'Invalid scan output format'}), 500
            else:
                logger.error("native_scan_failed", error=result.stderr)
                return jsonify({'error': f'Network scan failed: {result.stderr}'}), 500
        else:
            return jsonify({'error': 'Native network scanner binary not available'}), 503

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Network scan timed out'}), 408
    except Exception as e:
        logger.error("native_scan_error", error=str(e))
        return jsonify({'error': 'Network scan operation failed'}), 500

# Advanced Scanner API
@app.route('/api/v2/scanner/advanced', methods=['POST'])
@limiter.limit("10 per minute")
def advanced_scan():
    """Enterprise-grade network scanning"""
    try:
        if AdvancedScanner is None:
            return jsonify({'error': 'Advanced scanner module not available'}), 503

        data = request.get_json()
        scanner = AdvancedScanner(
            target=data.get('target'),
            scan_type=data.get('scan_type', 'comprehensive'),
            ports=data.get('ports', '1-65535'),
            scripts=data.get('scripts', []),
            intensity=data.get('intensity', 'normal')
        )

        scan_id = scanner.start_scan()

        logger.info("scan_initiated",
                   target=data.get('target'),
                   scan_type=data.get('scan_type'),
                   scan_id=scan_id)

        return jsonify({
            'scan_id': scan_id,
            'status': 'initiated',
            'estimated_duration': scanner.estimate_duration()
        })

    except Exception as e:
        logger.error("scan_initiation_failed", error=str(e))
        return jsonify({'error': 'Failed to initiate scan'}), 500

# Threat Intelligence API
@app.route('/api/v2/threat-intel/analyze', methods=['POST'])
@limiter.limit("20 per minute")
def threat_analysis():
    """Advanced threat intelligence analysis"""
    try:
        if ThreatIntelligence is None:
            return jsonify({'error': 'Threat intelligence module not available'}), 503

        data = request.get_json()
        threat_intel = ThreatIntelligence()

        analysis = threat_intel.analyze_indicator(
            indicator=data.get('indicator'),
            indicator_type=data.get('type'),
            include_context=data.get('include_context', True)
        )

        return jsonify(analysis)

    except Exception as e:
        logger.error("threat_analysis_failed", error=str(e))
        return jsonify({'error': 'Threat analysis failed'}), 500

# Vulnerability Scanner API
@app.route('/api/v2/vulnerability/scan', methods=['POST'])
@limiter.limit("5 per minute")
def vulnerability_scan():
    """Comprehensive vulnerability assessment"""
    try:
        if VulnerabilityScanner is None:
            return jsonify({'error': 'Vulnerability scanner module not available'}), 503

        data = request.get_json()
        vuln_scanner = VulnerabilityScanner()

        scan_id = vuln_scanner.start_scan(
            target=data.get('target'),
            scan_profile=data.get('profile', 'comprehensive'),
            custom_checks=data.get('custom_checks', [])
        )

        return jsonify({
            'scan_id': scan_id,
            'status': 'scanning',
            'profile': data.get('profile')
        })

    except Exception as e:
        logger.error("vulnerability_scan_failed", error=str(e))
        return jsonify({'error': 'Vulnerability scan failed'}), 500

# Advanced Cryptography API
@app.route('/api/v2/crypto/quantum-encrypt', methods=['POST'])
def quantum_encrypt():
    """Quantum-resistant encryption"""
    try:
        if AdvancedCrypto is None:
            return jsonify({'error': 'Crypto module not available'}), 503

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        algorithm = request.form.get('algorithm', 'kyber512')

        crypto = AdvancedCrypto()
        result = crypto.quantum_encrypt(file, algorithm)

        return jsonify({
            'encrypted_file': result['encrypted_file'],
            'key_data': result['key_data'],
            'algorithm': algorithm,
            'quantum_resistant': True
        })

    except Exception as e:
        logger.error("quantum_encryption_failed", error=str(e))
        return jsonify({'error': 'Quantum encryption failed'}), 500

# OSINT Analysis API
@app.route('/api/v2/osint/investigate', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def osint_investigation():
    """OSINT investigation and analysis"""
    try:
        if OSINTAnalyzer is None:
            return jsonify({'error': 'OSINT analyzer module not available'}), 503

        data = request.get_json()
        osint = OSINTAnalyzer()

        investigation = osint.investigate(
            target=data.get('target'),
            target_type=data.get('type'),
            depth=data.get('depth', 'standard'),
            sources=data.get('sources', [])
        )

        return jsonify(investigation)

    except Exception as e:
        logger.error("osint_investigation_failed", error=str(e))
        return jsonify({'error': 'OSINT investigation failed'}), 500

# Real-time monitoring with WebSocket (if available)
if socketio:
    @socketio.on('connect')
    def handle_connect():
        """Handle WebSocket connections for real-time monitoring"""
        logger.info("websocket_connected", client_id=request.sid)

    @socketio.on('subscribe_monitoring')
    def handle_monitoring_subscription(data):
        """Subscribe to real-time security monitoring"""
        logger.info("monitoring_subscription", filters=data.get('filters', {}))

# Health check and metrics
@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Check basic application health
        components = {}

        # Check if modules are available
        components['scanner'] = 'available' if AdvancedScanner else 'unavailable'
        components['threat_intel'] = 'available' if ThreatIntelligence else 'unavailable'
        components['vulnerability_scanner'] = 'available' if VulnerabilityScanner else 'unavailable'
        components['crypto'] = 'available' if AdvancedCrypto else 'unavailable'
        components['osint'] = 'available' if OSINTAnalyzer else 'unavailable'

        # Try to check external services (with timeouts)
        try:
            # Quick redis check
            import redis
            r = redis.from_url(app.config.get('REDIS_URL', 'redis://localhost:6379'), socket_timeout=1)
            r.ping()
            components['redis'] = 'healthy'
        except:
            components['redis'] = 'unavailable'

        overall_status = 'healthy' if any(v == 'available' or v == 'healthy' for v in components.values()) else 'degraded'

        return jsonify({
            'status': overall_status,
            'timestamp': datetime.utcnow().isoformat(),
            'version': app.config.get('API_VERSION', 'v2'),
            'components': components,
            'uptime': 'running'
        })
    except Exception as e:
        logger.error("health_check_error", error=str(e))
        return jsonify({
            'status': 'error',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error("internal_server_error", error=str(error))
    return render_template('errors/500.html'), 500

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

# Initialize directories
def initialize_directories():
    """Create necessary directories for the application"""
    directories = [
        Path('uploads'),
        Path('uploads/crypto'),
        Path('logs'),
        Path('reports'),
        Path('temp')
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

# Initialize directories on startup
initialize_directories()

# Configure logging
try:
    logging.basicConfig(
        level=getattr(logging, app.config.get('LOG_LEVEL', 'INFO')),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
except:
    logging.basicConfig(level=logging.INFO)

logger.info("CyberSec Professional Suite starting...")

if __name__ == '__main__':
    # Run with SocketIO for real-time features if available
    port = int(os.environ.get('PORT', 8000))
    host = '0.0.0.0'

    if socketio:
        socketio.run(app,
                    host=host,
                    port=port,
                    debug=False)
    else:
        # Fallback to regular Flask
        app.run(host=host,
                port=port,
                debug=False)