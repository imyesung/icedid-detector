# detectors/base_detector.py
from abc import ABC, abstractmethod


class BaseDetector(ABC):
    """
    모든 Detector(감지기)가 상속해야 할 공통 추상 클래스.
    각 악성코드별 Detector는 이 클래스를 상속받아 'detect' 메서드를 구현한다.
    """

    @abstractmethod
    def detect(self, content: str, url: str = "") -> dict:
        """
        악성 코드 탐지 로직을 수행하는 메서드.

        파라미터:
            content (str): 분석 대상 HTML, JS 등
            url (str): (옵션) 분석 대상 URL

        반환:
            dict: {
                'malware_detected': bool,
                'malware_type': str or None,
                'description': str,
                'confidence_score': int,
                'detected_patterns': list
            }
        """
        pass