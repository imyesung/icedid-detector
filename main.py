# main.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import MalwareDetectionEngine

app = Flask(__name__)
CORS(app)

# 엔진 초기화: config/rules.json 경로 사용
scanner_engine = MalwareDetectionEngine(config_path="config/rules.json")

@app.route("/scan", methods=["POST"])
def scan_route():
    """
    요청 JSON: {
      'url': '...',
      'content': '...'
    }
    """
    data = request.json or {}
    content = data.get("content", "")
    url = data.get("url", "")

    # 감지 수행
    results = scanner_engine.run_detection(content, url)

    # 엔진 결과를 그대로 반환
    return jsonify(results)

if __name__ == "__main__":
    # Flask 서버 실행 (개발 환경)
    app.run(debug=True, port=5000)