# static_detectors/icedid_detector.py
import re
import logging
from static_detectors.base_detector import BaseDetector

class IcedIDDetector(BaseDetector):
    """
    IcedID (BokBot) 악성코드 감지를 위한 정적 분석 모듈.
    JSON 설정 파일에서 패턴과 키워드를 받아서 분석합니다.
    """
    def __init__(self, config_rules: dict):
        self.url_patterns = [re.compile(p) for p in config_rules.get("url_patterns", [])]
        self.script_patterns = [re.compile(p) for p in config_rules.get("script_patterns", [])]
        self.content_keywords = config_rules.get("content_keywords", [])
        logging.info("IcedIDDetector initialized with %d URL patterns, %d script patterns, and %d keywords.",
                     len(self.url_patterns), len(self.script_patterns), len(self.content_keywords))

    def detect(self, content: str, url: str = "") -> dict:
        result = {
            "malware_detected": False,
            "malware_type": None,
            "description": "No malware detected in static analysis.",
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

        # 콘텐츠 키워드 검사 (대소문자 구분 없이)
        content_lower = content.lower()
        for keyword in self.content_keywords:
            if keyword.lower() in content_lower:
                msg = f"Suspicious keyword: {keyword}"
                result["detected_patterns"].append(msg)
                result["confidence_score"] += 20
                logging.info(msg)

        # 임계치 이상이면 악성으로 판정 (여기서는 단순 예시)
        if result["confidence_score"] >= 50:
            result["malware_detected"] = True
            result["malware_type"] = "IcedID"
            result["description"] = "Static indicators suggest potential IcedID malware."
        
        return result