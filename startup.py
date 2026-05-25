#!/usr/bin/env python3
"""
Startup script for CyberSec Professional Suite
Handles initialization and error checking before launching the main application
"""

import os
import sys
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def check_environment():
    """Check if the environment is properly set up"""
    print("🔧 Checking environment...")

    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False

    print(f"✅ Python version: {sys.version}")

    # Check required environment variables
    port = os.environ.get('PORT', '10000')
    print(f"✅ Port: {port}")

    # Check if we're in a production environment
    env = os.environ.get('FLASK_ENV', 'production')
    print(f"✅ Environment: {env}")

    # Check for native binaries
    encrypt_binary = Path('backend/c/encrypt')
    sniffer_binary = Path('backend/cpp/sniffer')

    if encrypt_binary.exists():
        print(f"✅ Native encryption binary available")
    else:
        print(f"⚠️  Native encryption binary not found")

    if sniffer_binary.exists():
        print(f"✅ Native sniffer binary available")
    else:
        print(f"⚠️  Native sniffer binary not found")

    return True

def setup_directories():
    """Create necessary directories"""
    print("📁 Setting up directories...")

    directories = [
        Path('uploads'),
        Path('uploads/crypto'),
        Path('logs'),
        Path('reports'),
        Path('temp')
    ]

    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"✅ Created directory: {directory}")
        except Exception as e:
            print(f"⚠️  Could not create directory {directory}: {e}")

def test_imports():
    """Test if critical imports work"""
    print("🔍 Testing imports...")

    try:
        import flask
        print(f"✅ Flask version: {flask.__version__}")
    except ImportError as e:
        print(f"❌ Flask import failed: {e}")
        return False

    try:
        import gunicorn
        print(f"✅ Gunicorn available")
    except ImportError as e:
        print(f"❌ Gunicorn import failed: {e}")
        return False

    return True

def main():
    """Main startup function"""
    print("🚀 Starting CyberSec Professional Suite...")
    print("=" * 50)

    if not check_environment():
        print("❌ Environment check failed")
        sys.exit(1)

    if not test_imports():
        print("❌ Import test failed")
        sys.exit(1)

    setup_directories()

    print("=" * 50)
    print("✅ All checks passed!")
    print("🚀 Starting application...")

    # Import and run the app
    try:
        from app import app, socketio

        port = int(os.environ.get('PORT', 10000))
        host = '0.0.0.0'

        print(f"🌐 Starting server on {host}:{port}")

        if socketio:
            print("🔌 WebSocket support enabled")
            socketio.run(app, host=host, port=port, debug=False)
        else:
            print("⚡ Running in Flask-only mode")
            app.run(host=host, port=port, debug=False)

    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()