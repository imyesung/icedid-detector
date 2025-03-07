# engine.py
import os
import json
import logging
import yara
from static_detectors.icedid_detector import IcedIDDetector
from utils.rule_loader import load_yara_rules_from_directory
from utils.config_loader import load_detector_config

class MalwareDetectionEngine:
    """
    JSON 설정과 YARA 규칙 파일을 불러와, 정적 분석(Detectors)과 동적 분석(추후 통합)을 실행하는 엔진.
    """
    def __init__(self, config_path="config/static/icedid.json", yara_dir="config/rules"):
        # JSON 설정 로드 (정적 분석 파라미터)
        self.config_data = load_detector_config(config_path)
        logging.info("Static detector config loaded from %s", config_path)

        # YARA 규칙 자동 로딩
        self.yara_rules = load_yara_rules_from_directory(yara_dir)
        logging.info("YARA rules loaded from %s", yara_dir)

        # IcedID 정적 Detector 초기화
        icedid_config = self.config_data.get("icedid", {})
        self.icedid_detector = IcedIDDetector(config_rules=icedid_config)
        # 동적 분석 모듈은 추후 dynamic_analyzers 폴더 내에서 관리

    def run_detection(self, content: str, url: str = "") -> dict:
        results = {}

        # 정적 분석 실행
        static_result = self.icedid_detector.detect(content, url)
        results["static_analysis"] = static_result

        # YARA 규칙 적용 (정적 분석의 추가 검증)
        yara_results = []
        for rule_name, rule in self.yara_rules.items():
            try:
                matches = rule.match(data=content.encode("utf-8"))
                if matches:
                    yara_results.append({
                        "yara_rule": rule_name,
                        "matches": [match.rule for match in matches],
                        "description": f"Triggered YARA rule: {rule_name}"
                    })
                    logging.info("YARA rule %s matched", rule_name)
            except Exception as e:
                logging.error("Error during YARA matching for rule %s: %s", rule_name, e)
        results["yara_analysis"] = yara_results

        # 동적 분석 결과 (추후 구현 예정)
        results["dynamic_analysis"] = "Dynamic analysis not implemented yet."

        return {"detection_summary": results}