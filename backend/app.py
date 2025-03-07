# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib

app = Flask(__name__)
CORS(app)  # Enable CORS for Chrome extension integration


# Simple IcedID detection function (placeholder)
def detect_icedid(content):
    # Basic detection logic - to be enhanced
    suspicious_patterns = [
        "IcedID signature",
        "BokBot signature",
        # Add more signatures
    ]

    for pattern in suspicious_patterns:
        if pattern.lower() in content.lower():
            return True
    return False


@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    content = data.get('content', '')
    url = data.get('url', '')

    # Perform detection
    is_malicious = detect_icedid(content)

    result = {
        "malware_detected": is_malicious,
        "malware_type": "IcedID" if is_malicious else None,
        "description": "Banking trojan detected" if is_malicious else "No malware detected"
    }

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, port=5000)