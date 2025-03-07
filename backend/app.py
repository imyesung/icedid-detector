from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import MalwareDetectionEngine

app = Flask(__name__)
CORS(app)  # Chrome 확장프로그램 통합을 위한 CORS 활성화
scanner_engine = MalwareDetectionEngine(config_path="../config/rules.json")

@app.route('/scan', methods=['POST'])
def scan():
    """
    멀웨어 탐지 엔드포인트
    
    요청 형식:
    {
        "content": "검사할 컨텐츠",
        "url": "검사할 URL" (선택사항)
    }
    """
    data = request.json or {}
    content = data.get('content', '')
    url = data.get('url', '')

    results = scanner_engine.run_detection(content, url)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)