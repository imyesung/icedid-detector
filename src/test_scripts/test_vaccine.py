import os
import yara
import psutil

# YARA 룰 (간단한 패턴 기반 탐지)
RULES = """
rule RAT_Detection {
    strings:
        $rat1 = "RAT_CLIENT"
        $rat2 = "C2_SERVER"
    condition:
        any of ($*)
}
"""

# YARA 룰 컴파일
rules = yara.compile(source=RULES)

# 1️⃣ 파일 검사 함수
def scan_files(directory):
    print("[+] Scanning files for RAT signatures...")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                matches = rules.match(file_path)
                if matches:
                    print(f"[!] Detected RAT in {file_path}")
            except:
                continue
    print("[+] File scan completed.")

# 2️⃣ 실행 중인 프로세스 검사 함수
def scan_processes():
    print("[+] Scanning running processes...")
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            proc_name = process.info['name']
            proc_exe = process.exe()
            with open(proc_exe, 'rb') as f:
                content = f.read()
                if rules.match(data=content):
                    print(f"[!] RAT detected in running process: {proc_name} (PID: {process.info['pid']})")
        except:
            continue
    print("[+] Process scan completed.")

if __name__ == "__main__":
    scan_files("./")  # 현재 디렉토리에서 RAT 탐색
    scan_processes()  # 실행 중인 프로세스 검사
