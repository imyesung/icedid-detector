# utils/config_loader.py
import json

def load_detector_config(json_path: str) -> dict:
    """
    주어진 JSON 설정 파일을 로드하여 딕셔너리로 반환합니다.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)