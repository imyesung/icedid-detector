# backend/app.py
import os
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import MalwareDetectionEngine
from dotenv import load_dotenv

# 상위 폴더에 있는 .env 파일 로드
load_dotenv(os.path.join(os.path.dirname(__file__), "../.env"))

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "default-secret-key")
    CORS(app)

    # 정적 분석 설정 및 YARA 규칙 경로 (환경변수 또는 기본값)
    static_config_path = os.getenv("STATIC_CONFIG_PATH", "config/static/icedid.json")
    yara_rules_dir = os.getenv("YARA_RULES_DIR", "config/rules")
    engine = MalwareDetectionEngine(config_path=static_config_path, yara_dir=yara_rules_dir)

    @app.route('/scan', methods=['POST'])
    def scan():
        data = request.get_json() or {}
        content = data.get('content', '').strip()
        url = data.get('url', '').strip()

        if not content and not url:
            return jsonify({"error": "Either content or url is required."}), 400

        results = engine.run_detection(content, url)
        logging.info(f"Scan request processed: content preview={content[:30]}, url={url}")
        return jsonify(results)

    return app