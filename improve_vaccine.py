import hashlib
import os
import yara
import pefile
import subprocess

# 악성코드 해시 데이터베이스
MALWARE_HASHES = {
    "db349b97c37d22f5ea1d1841e3c89eb4": "WannaCry Ransomware",
    "b7f40437fa1b9e29c54e3f65ddff4b7b": "AsyncRAT"
}

# YARA 룰 추가 (RAT, 랜섬웨어, 키로거 탐지)
YARA_RULES = """
rule RAT_Detection {
    strings:
        $rat1 = "RAT_CLIENT"
        $rat2 = "C2_SERVER"
    condition:
        any of ($*)
}

rule Ransomware_Detection {
    strings:
        $ransom1 = "AES-256"
        $ransom2 = "EncryptFile"
        $ransom3 = "WannaCry"
    condition:
        any of ($*)
}
"""

rules = yara.compile(source=YARA_RULES)

# SHA-256 해시 계산 함수
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        sha256.update(f.read())
    return sha256.hexdigest()

# PE 파일 검사 (패킹 여부, Import Table 분석)
def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if "Crypt" in entry.dll.decode('utf-8', errors='ignore'):
                print(f"[!] Possible encryption functions detected in {file_path}")
    except Exception as e:
        print(f"[-] PE analysis failed: {str(e)}")

# 파일 검사 함수
def scan_files(directory):
    print("[+] Scanning files for malware signatures...")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_hash = calculate_hash(file_path)
                if file_hash in MALWARE_HASHES:
                    print(f"[!] Known malware detected: {MALWARE_HASHES[file_hash]} in {file_path}")
                
                matches = rules.match(file_path)
                if matches:
                    print(f"[!] Potential malware detected in {file_path}")
                
                analyze_pe(file_path)
            except:
                continue
    print("[+] File scan completed.")
