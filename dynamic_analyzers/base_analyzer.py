# dynamic_analyzers/base_analyzer.py
from abc import ABC, abstractmethod

class BaseAnalyzer(ABC):
    """
    모든 동적 분석 모듈이 상속해야 하는 추상 클래스.
    """
    @abstractmethod
    def analyze(self, content: str, url: str = "") -> dict:
        pass