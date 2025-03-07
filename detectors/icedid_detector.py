# detectors/icedid_detector.py
import re
import logging
from detectors.base_detector import BaseDetector

class IcedIDDetector(BaseDetector):
    """
    IcedID (aka BokBot) 악성코드를 감지하기 위한 Detector.
    config/rules.json에서 IcedID 관련 정규식, 키워드 등을 받아와서 사용.
    """
    def __init__(self, config_rules: dict):
        # config_rules로부터 패턴 및 키워드 로드
        self.url_patterns = [re.compile(p) for p in config_rules.get("url_patterns", [])]
        self.script_patterns = [re.compile(p) for p in config_rules.get("script_patterns", [])]
        self.content_keywords = config_rules.get("content_keywords", [])
        logging.info("IcedIDDetector initialized.")

    def detect(self, content: str, url: str = "") -> dict:
        """
        content와 url을 분석하여 IcedID 악성코드 의심 지표 탐지.
        """
        result = {
            "malware_detected": False,
            "malware_type": None,
            "description": "No malware detected",
            "confidence_score": 0,
            "detected_patterns": []
        }

        # URL 패턴 검사
        for pattern in self.url_patterns:
            if pattern.search(url):
                msg = f"Suspicious URL pattern: {pattern.pattern}"
                result["detected_patterns"].append(msg)
                result["confidence_score"] += 30
                logging.info(msg)

        # 스크립트 패턴 검사
        for pattern in self.script_patterns:
            if pattern.search(content):
                msg = f"Malicious script pattern: {pattern.pattern}"
                result["detected_patterns"].append(msg)
                result["confidence_score"] += 40
                logging.info(msg)

        # 콘텐츠 키워드 검사 (대소문자 무시)
        content_lower = content.lower()
        for keyword in self.content_keywords:
            if keyword.lower() in content_lower:
                msg = f"Suspicious keyword: {keyword}"
                result["detected_patterns"].append(msg)
                result["confidence_score"] += 20
                logging.info(msg)

        # 최종 판단: confidence_score가 일정 임계치 이상이면 악성으로 판정
        if result["confidence_score"] >= 50:
            result["malware_detected"] = True
            result["malware_type"] = "IcedID"
            result["description"] = "Potential IcedID malware detected."

        return result