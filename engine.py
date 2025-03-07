# engine.py
import json
import logging
from detectors.icedid_detector import IcedIDDetector


# from detectors.emotet_detector import EmotetDetector  # 필요 시 주석 해제
# etc.

class MalwareDetectionEngine:
    """
    여러 Detector를 로드 및 관리하여, 주어진 content/url을 종합 분석한다.
    """

    def __init__(self, config_path="config/rules.json"):
        """
        config_path: JSON 형태의 규칙 파일 경로
        """
        with open(config_path, "r", encoding="utf-8") as f:
            self.config_data = json.load(f)

        logging.basicConfig(level=logging.INFO)

        # IcedID Detector
        icedid_rules = self.config_data.get("icedid", {})
        self.icedid_detector = IcedIDDetector(config_rules=icedid_rules)

        # 필요한 경우, 다른 악성코드 Detector도 로드
        # emotet_rules = self.config_data.get("emotet", {})
        # self.emotet_detector = EmotetDetector(config_rules=emotet_rules)

    def run_detection(self, content: str, url: str = "") -> dict:
        """
        등록된 모든 Detector에 대해 탐지 실행 후, 결과를 묶어서 반환한다.
        """
        final_results = []

        # 1. IcedID 탐지
        icedid_result = self.icedid_detector.detect(content, url)
        final_results.append(icedid_result)

        # 2. 다른 악성코드 감지 결과도 추가
        # emotet_result = self.emotet_detector.detect(content, url)
        # final_results.append(emotet_result)

        # 간단히 리스트 형태로 묶어서 반환.
        # 필요하다면 aggregator 모듈로 종합 점수 계산 등을 수행할 수 있음.
        return {
            "detection_summary": final_results
        }