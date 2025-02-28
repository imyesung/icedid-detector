import psutil
import subprocess

# 탐지할 의심스러운 API 패턴
SUSPICIOUS_APIS = ["CreateRemoteThread", "WriteProcessMemory", "RegCreateKeyExW"]

# 실행 중인 프로세스 검사
def scan_processes():
    print("[+] Scanning running processes...")
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            proc_name = process.info['name']
            proc_exe = process.exe()
            result = subprocess.run(["strings", proc_exe], capture_output=True, text=True)
            
            for api in SUSPICIOUS_APIS:
                if api in result.stdout:
                    print(f"[!] Suspicious API detected in {proc_name} (PID: {process.info['pid']})")
        except:
            continue
    print("[+] Process scan completed.")

scan_processes()
