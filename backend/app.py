import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import MalwareDetectionEngine
import os
from dotenv import load_dotenv

# 현재 폴더 기준으로 .env 로드
load_dotenv(os.path.join(os.path.dirname(__file__), "../.env"))

# 환경 변수 읽기
FLASK_ENV = os.getenv("FLASK_ENV", "production")
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
CONFIG_PATH = os.getenv("CONFIG_PATH", "../config/rules.json")
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)
CORS(app)  # CORS 활성화

# 환경 변수에서 config 경로를 받아와 설정
scanner_engine = MalwareDetectionEngine(config_path=CONFIG_PATH)

@app.route('/scan', methods=['POST'])
def scan():
    """
    멀웨어 탐지 엔드포인트
    """
    try:
        data = request.json or {}
        content = data.get('content', '').strip()
        url = data.get('url', '').strip()

        if not content and not url:
            return jsonify({"error": "content 또는 url 중 하나는 필수입니다."}), 400

        results = scanner_engine.run_detection(content, url)

        logging.info(f"Scan request - content: {content[:30]}, url: {url}")  # 앞 30자만 로깅
        return jsonify(results)
    
    except Exception as e:
        logging.error(f"Error during scanning: {str(e)}")
        return jsonify({"error": "서버 내부 오류"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=int(os.getenv("PORT", 5000)))