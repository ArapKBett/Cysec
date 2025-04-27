from flask import Flask, render_template, request, jsonify, send_file, session
from modules.sniffer import PacketSniffer
from modules.password_audit import PasswordAuditor
from modules.ids import IDS
from modules.port_scanner import PortScanner
from modules.crypto import FileCrypto
import threading
import os
import secrets
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Set secret key for session management, using environment variable for security
# Render will provide this via environment variables in the dashboard
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Global states to track tool status
tool_states = {
    'sniffer': {'running': False, 'instance': None},
    'scanner': {'running': False, 'instance': None}
}

@app.route('/')
def index():
    # Render the main index page
    return render_template('index.html')

@app.route('/tools/<tool>')
def tool(tool):
    # Serve specific tool pages or return 404 if tool is invalid
    if tool not in ['sniffer', 'passwords', 'ids', 'scanner', 'crypto']:
        return render_template('404.html'), 404
    return render_template(f'tools/{tool}.html')

# Packet Sniffer Endpoints
@app.route('/sniffer/control', methods=['POST'])
def sniffer_control():
    if request.method == 'POST':
        action = request.json.get('action')
        if action == 'start':
            interface = request.json.get('interface', 'eth0')
            # Note: PacketSniffer may require root privileges or specific libraries (e.g., libpcap)
            # Render's containerized environment may restrict this; test thoroughly
            tool_states['sniffer']['instance'] = PacketSniffer(interface)
            thread = threading.Thread(target=tool_states['sniffer']['instance'].start)
            thread.start()
            tool_states['sniffer']['running'] = True
            return jsonify({'status': 'running'})
        elif action == 'stop':
            tool_states['sniffer']['instance'].stop()
            tool_states['sniffer']['running'] = False
            return jsonify({'status': 'stopped', 'stats': tool_states['sniffer']['instance'].get_stats()})
    return jsonify({'error': 'Invalid request'}), 400

# Password Auditor Endpoint
@app.route('/check-password', methods=['POST'])
def check_password():
    password = request.form.get('password')
    auditor = PasswordAuditor()
    return jsonify(auditor.analyze(password))

# Port Scanner Endpoints
@app.route('/scanner/start', methods=['POST'])
def start_scan():
    target = request.json.get('target')
    port_range = request.json.get('range', '1-1024')
    # Note: PortScanner may face restrictions in Render due to network policies
    # Test and consider disabling if it fails in production
    tool_states['scanner']['instance'] = PortScanner(target, port_range)
    thread = threading.Thread(target=tool_states['scanner']['instance'].run)
    thread.start()
    return jsonify({'status': 'scanning'})

@app.route('/scanner/progress')
def scan_progress():
    if tool_states['scanner']['instance']:
        return jsonify(tool_states['scanner']['instance'].get_progress())
    return jsonify({'error': 'No active scan'}), 404

# File Crypto Endpoints
@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    crypto = FileCrypto()
    # Note: Ensure Render's temporary disk storage supports file operations
    # For large files, consider external storage (e.g., AWS S3)
    key, encrypted_path = crypto.encrypt(file)
    return jsonify({'key': key.decode(), 'filename': encrypted_path})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    key = request.form.get('key')
    crypto = FileCrypto()
    decrypted_path = crypto.decrypt(file, key.encode())
    return send_file(decrypted_path, as_attachment=True)

# Removed the `if __name__ == '__main__':` block
# Render uses `gunicorn` (specified in Procfile) to run the app, not Flask's development server
# The `ssl_context='adhoc'` was for local debugging; Render provides HTTPS automatically
