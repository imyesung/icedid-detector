## 실행 방법 및 테스트

1️⃣ 테스트 환경 준비

```
pip install yara-python psutil
```

2️⃣ C2 서버 실행<br>
C2 서버를 먼저 실행해야, RAT이 C2 서버에 연결될 수 있습니다.

```
python create_C2.py
```

3️⃣ RAT 실행

```
python test_rat.py
```

- `test_rat.py`는 C2 서버로 연결을 시도한 후, 명령어를 기다림.<br>
- `creat_C2.py` 창에서 명령어 입력 가능 (`ls`, `whoami`, `exit` 등).<br>

4️⃣ C2 탐지 script 실행

```
python detection_C2.py
```

5️⃣ 실행 중인 프로세스 모니터링

```
python real_time_overwatch.py
```

```
[+] Scanning running processes...
[+] Process scan completed.
```

6️⃣ 파일 및 프로세스 기반 악성코드 탐지<br>
이제 파일 기반 탐지 및 PE 분석을 실행합니다.

```
python improve_vaccine.py
```

📌 실행 결과 예시<br>

```
[+] Scanning files for RAT signatures...
[!] Detected RAT in ./improve_vaccine.py
[!] Detected RAT in ./test_rat.py
[!] Detected RAT in ./test_vaccine.py
[+] File scan completed.
[+] Scanning running processes...
[+] Process scan completed.
```
