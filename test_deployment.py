#!/usr/bin/env python3
"""
Test script to verify deployment readiness for CyberSec Professional Suite
Run this before deploying to catch issues early
"""

import sys
import os
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / 'backend' / 'python'))

def test_imports():
    """Test all critical imports"""
    print("🔍 Testing imports...")
    failures = []

    tests = [
        ('flask', 'Flask framework'),
        ('gunicorn', 'WSGI server'),
        ('redis', 'Redis client'),
        ('requests', 'HTTP client'),
        ('cryptography', 'Cryptography library'),
        ('structlog', 'Structured logging')
    ]

    for module, description in tests:
        try:
            __import__(module)
            print(f"✅ {module:<20} - {description}")
        except ImportError as e:
            print(f"❌ {module:<20} - {description} - FAILED: {e}")
            failures.append(module)

    return len(failures) == 0

def test_app_creation():
    """Test if the Flask app can be created successfully"""
    print("\n🏗️  Testing Flask app creation...")

    try:
        from config import get_config
        print("✅ Config module loaded")

        from app import app
        print("✅ Flask app created")

        # Test app configuration
        with app.app_context():
            print(f"✅ App name: {app.name}")
            print(f"✅ Secret key configured: {'Yes' if app.secret_key else 'No'}")

        return True
    except Exception as e:
        print(f"❌ Flask app creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_health_endpoint():
    """Test if health endpoint works"""
    print("\n🏥 Testing health endpoint...")

    try:
        from app import app

        with app.test_client() as client:
            response = client.get('/health')
            data = response.get_json()

            if response.status_code == 200:
                print(f"✅ Health check returns 200")
                print(f"✅ Status: {data.get('status', 'unknown')}")
                return True
            else:
                print(f"❌ Health check failed with status {response.status_code}")
                return False

    except Exception as e:
        print(f"❌ Health endpoint test failed: {e}")
        return False

def test_file_structure():
    """Test if required files exist"""
    print("\n📁 Testing file structure...")

    required_files = [
        'app.py',
        'config.py',
        'requirements.txt',
        'startup.py',
        'Procfile',
        'backend/c/encrypt.c',
        'backend/cpp/sniffer.cpp',
        'backend/python/modules'
    ]

    all_exist = True
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")
            all_exist = False

    return all_exist

def test_environment_variables():
    """Test environment variable handling"""
    print("\n🌍 Testing environment variables...")

    # Test with common production variables
    test_vars = {
        'PORT': '10000',
        'FLASK_ENV': 'production'
    }

    for var, value in test_vars.items():
        old_value = os.environ.get(var)
        os.environ[var] = value
        print(f"✅ Set {var}={value}")

        # Restore old value if it existed
        if old_value:
            os.environ[var] = old_value
        else:
            os.environ.pop(var, None)

    return True

def main():
    """Run all tests"""
    print("🚀 CyberSec Professional Suite - Deployment Test")
    print("=" * 60)

    tests = [
        ("File Structure", test_file_structure),
        ("Python Imports", test_imports),
        ("Environment Variables", test_environment_variables),
        ("Flask App Creation", test_app_creation),
        ("Health Endpoint", test_health_endpoint),
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n{'=' * 20} {test_name} {'=' * 20}")
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)

    passed = 0
    total = len(results)

    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if success:
            passed += 1

    print(f"\n📈 Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Ready for deployment.")
        return 0
    else:
        print(f"⚠️  {total - passed} test(s) failed. Fix issues before deployment.")
        return 1

if __name__ == '__main__':
    exit(main())