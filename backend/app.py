# backend/app.py
import os
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import MalwareDetectionEngine
from dotenv import load_dotenv

# 상위 폴더에 위치한 .env 파일 로드
load_dotenv(os.path.join(os.path.dirname(__file__), "../.env"))

# 환경 변수 읽기
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
CONFIG_PATH = os.getenv("CONFIG_PATH", "../config/rules.json")

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    CORS(app)

    # 악성코드 탐지 엔진 인스턴스 생성
    detection_engine = MalwareDetectionEngine(config_path=CONFIG_PATH)

    @app.route('/scan', methods=['POST'])
    def scan():
        """
        악성코드 탐지 API 엔드포인트  
        요청 JSON에는 'content'와/또는 'url'을 포함해야 함.
        """
        try:
            data = request.get_json() or {}
            content = data.get('content', '').strip()
            url = data.get('url', '').strip()

            if not content and not url:
                return jsonify({"error": "content 또는 url 중 하나는 필수입니다."}), 400

            results = detection_engine.run_detection(content, url)
            logging.info(f"Scan request - content preview: {content[:30]}, url: {url}")
            return jsonify(results)
        except Exception as e:
            logging.error(f"Error during scanning: {str(e)}")
            return jsonify({"error": "서버 내부 오류"}), 500

    return app