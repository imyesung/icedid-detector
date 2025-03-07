# engine.py
import os
import json
import logging
import yara
from detectors.icedid_detector import IcedIDDetector
from utils.rule_loader import load_yara_rules_from_directory
from utils.config_loader import load_detector_config

class MalwareDetectionEngine:
    """
    MalwareDetectionEngine은 JSON 설정과 YARA 규칙 파일들을 자동으로 불러와,
    등록된 각 Detector 및 YARA 기반 분석을 수행합니다.
    """
    def __init__(self, config_path="config/detectors.json", yara_dir="config/rules"):
        # JSON 설정 로드
        self.config_data = load_detector_config(config_path)
        logging.info("Detector config loaded from %s", config_path)
        
        # YARA 규칙 로드 (모든 규칙 자동 로딩)
        self.yara_rules = load_yara_rules_from_directory(yara_dir)
        logging.info("YARA rules loaded from %s", yara_dir)

        # IcedID Detector 초기화 (예시)
        icedid_config = self.config_data.get("icedid", {})
        self.icedid_detector = IcedIDDetector(config_rules=icedid_config)
        # 필요한 경우 다른 Detector도 유사하게 초기화
        # 예: self.ransomware_x_detector = RansomwareXDetector(config_rules=self.config_data.get("ransomware_x", {}))

    def run_detection(self, content: str, url: str = "") -> dict:
        """
        등록된 Detector와 YARA 규칙을 모두 실행한 후 결과를 종합하여 반환합니다.
        """
        results = []

        # IcedID 기반 정적 분석
        icedid_result = self.icedid_detector.detect(content, url)
        results.append(icedid_result)

        # YARA 규칙 적용
        for rule_name, rule in self.yara_rules.items():
            try:
                yara_matches = rule.match(data=content.encode("utf-8"))
                if yara_matches:
                    results.append({
                        "yara_rule": rule_name,
                        "yara_matches": [match.rule for match in yara_matches],
                        "description": f"Triggered YARA rule: {rule_name}"
                    })
                    logging.info("YARA rule %s matched.", rule_name)
            except Exception as e:
                logging.error("Error during YARA matching for rule %s: %s", rule_name, e)

        return {"detection_summary": results}