# run.py
import os
import logging
from backend.app import create_app

# 중앙 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=int(os.getenv("PORT", 5000)))