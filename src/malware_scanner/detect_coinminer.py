import hashlib
import os

import psutil
import yara

# Coinminer 악성코드 해시 데이터베이스
COINMINER_HASHES = {
    "ff2b4530e84a53dcb3a84bdb348d2df9": "XMRig Coinminer",
    "67e70bdfb0c8032acdb7fb68bbdb812a": "NiceHash Miner"
}

# YARA 룰 (Coinminer 탐지)
COINMINER_YARA_RULES = """
rule Coinminer_Detection {
    strings:
        $miner1 = "stratum+tcp"
        $miner2 = "xmr"
        $miner3 = "cryptonight"
    condition:
        any of ($*)
}
"""

rules = yara.compile(source=COINMINER_YARA_RULES)

# SHA-256 해시 계산 함수
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        sha256.update(f.read())
    return sha256.hexdigest()

# 실행 중인 프로세스 검사
def scan_processes():
    print("[+] Scanning running processes for Coinminer...")
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            proc_name = process.info['name']
            proc_exe = process.exe()
            with open(proc_exe, 'rb') as f:
                content = f.read()
                if rules.match(data=content):
                    print(f"[!] Coinminer detected in process: {proc_name} (PID: {process.info['pid']})")
        except:
            continue
    print("[+] Process scan completed.")

# 파일 검사 함수
def scan_files(directory):
    print("[+] Scanning files for Coinminer signatures...")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_hash = calculate_hash(file_path)
                if file_hash in COINMINER_HASHES:
                    print(f"[!] Known Coinminer detected: {COINMINER_HASHES[file_hash]} in {file_path}")
                
                matches = rules.match(file_path)
                if matches:
                    print(f"[!] Potential Coinminer detected in {file_path}")
            except:
                continue
    print("[+] File scan completed.")

if __name__ == "__main__":
    scan_files("./")  # 현재 디렉토리에서 Coinminer 탐색
    scan_processes()  # 실행 중인 프로세스 검사