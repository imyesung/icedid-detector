# utils/config_loader.py
import json
import os

def load_detector_config(json_path):
    """
    지정된 JSON 파일로부터 detector 설정을 로드합니다.
    반환값은 악성코드 종류별 설정을 포함하는 딕셔너리입니다.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)
    return config_data