#!/usr/bin/env python3
"""
dropper_detector.py
드로퍼 감지 스캐너
"""

import sys

def detect_dropper(file_path):
    # 드로퍼 예시 파일에 포함된 서명 문자열
    signature = "DROPper_EXAMPLE_SIGNATURE"
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[-] 파일 읽기 실패: {e}")
        return
    
    if signature in content:
        print(f"[!] {file_path} 파일에서 드로퍼 서명이 감지되었습니다.")
    else:
        print(f"[-] {file_path} 파일에서 드로퍼 서명이 발견되지 않았습니다.")

def main():
    if len(sys.argv) < 2:
        print("사용법: python dropper_detector.py <스캔할 파일>")
        sys.exit(1)
    
    file_to_scan = sys.argv[1]
    detect_dropper(file_to_scan)

if __name__ == "__main__":
    main()
