# static_detectors/base_detector.py
from abc import ABC, abstractmethod

class BaseDetector(ABC):
    """
    모든 정적 분석 Detector가 상속해야 할 추상 클래스
    """
    @abstractmethod
    def detect(self, content: str, url: str = "") -> dict:
        pass