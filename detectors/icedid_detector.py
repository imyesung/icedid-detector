# detectors/icedid_detector.py
import re
import logging
from detectors.base_detector import BaseDetector

class IcedIDDetector(BaseDetector):
    """
    IcedID(aka BokBot) 악성코드를 감지하기 위한 Detector.
    config/rules.json에서 IcedID 관련 규칙(정규식, 키워드 등)을 받아와서 사용한다.
    """

    def __init__(self, config_rules: dict):
        """
        파라미터:
            config_rules (dict): JSON에서 불러온 IcedID 관련 정규식·키워드 목록.
        """
        self.url_patterns = [re.compile(p) for p in config_rules.get("url_patterns", [])]
        self.script_patterns = [re.compile(p) for p in config_rules.get("script_patterns", [])]
        self.content_keywords = config_rules.get("content_keywords", [])
        logging.basicConfig(level=logging.INFO)

    def detect(self, content: str, url: str = "") -> dict:
        """
        IcedID 의심 지표를 찾고, 그 결과를 반환한다.
        """
        # 결과 기본 구조
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

        # 콘텐츠 키워드 검사 (대소문자 구분X)
        content_lower = content.lower()
        for keyword in self.content_keywords:
            if keyword.lower() in content_lower:
                msg = f"Suspicious keyword: {keyword}"
                result["detected_patterns"].append(msg)
                result["confidence_score"] += 20
                logging.info(msg)

        # 최종 점수 판단
        if result["confidence_score"] >= 50:
            result["malware_detected"] = True
            result["malware_type"] = "IcedID"
            result["description"] = "Banking trojan detected with IcedID characteristics"

        return result