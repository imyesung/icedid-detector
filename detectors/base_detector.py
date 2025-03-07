# detectors/base_detector.py
from abc import ABC, abstractmethod

class BaseDetector(ABC):
    """
    모든 악성코드 Detector가 상속해야 할 추상 클래스.
    각 Detector는 이 클래스를 상속받아 detect() 메서드를 구현해야 함.
    """
    @abstractmethod
    def detect(self, content: str, url: str = "") -> dict:
        """
        악성코드 탐지 로직을 수행.
        반환 예시:
            {
                'malware_detected': bool,
                'malware_type': str or None,
                'description': str,
                'confidence_score': int,
                'detected_patterns': list
            }
        """
        pass