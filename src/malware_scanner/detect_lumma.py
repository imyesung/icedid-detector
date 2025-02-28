import hashlib
import os

import psutil
import yara

# Lumma Stealer 악성코드 해시 데이터베이스
LUMMA_HASHES = {
    "a7b3c4d5e6f7890123456789abcdef12": "Lumma Stealer Variant 1",
    "b6a4e3f2d1c09876543210fedcba9876": "Lumma Stealer Variant 2"
}

# YARA 룰 (Lumma Stealer 탐지)
LUMMA_YARA_RULES = """
rule LummaStealer_Detection {
    strings:
        $lumma1 = "Discord_Token"
        $lumma2 = "CreditCard_Stealer"
        $lumma3 = "Browser_Passwords"
    condition:
        any of ($*)
}
"""

rules = yara.compile(source=LUMMA_YARA_RULES)

# SHA-256 해시 계산 함수
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        sha256.update(f.read())
    return sha256.hexdigest()

# 실행 중인 프로세스 검사
def scan_processes():
    print("[+] Scanning running processes for LummaStealer...")
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            proc_name = process.info['name']
            proc_exe = process.exe()
            with open(proc_exe, 'rb') as f:
                content = f.read()
                if rules.match(data=content):
                    print(f"[!] LummaStealer detected in process: {proc_name} (PID: {process.info['pid']})")
        except:
            continue
    print("[+] Process scan completed.")

# 파일 검사 함수
def scan_files(directory):
    print("[+] Scanning files for LummaStealer signatures...")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_hash = calculate_hash(file_path)
                if file_hash in LUMMA_HASHES:
                    print(f"[!] Known LummaStealer detected: {LUMMA_HASHES[file_hash]} in {file_path}")
                
                matches = rules.match(file_path)
                if matches:
                    print(f"[!] Potential LummaStealer detected in {file_path}")
            except:
                continue
    print("[+] File scan completed.")

if __name__ == "__main__":
    scan_files("./")  # 현재 디렉토리에서 Lumma Stealer 탐색
    scan_processes()  # 실행 중인 프로세스 검사
