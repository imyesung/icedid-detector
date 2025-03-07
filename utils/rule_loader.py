# utils/rule_loader.py
import os
import logging
import yara

def load_yara_rules_from_directory(directory):
    """
    지정된 디렉토리에서 .yar 확장자를 가진 모든 YARA 규칙 파일을 자동으로 로드합니다.
    반환값은 { rule_name: compiled_rule } 형태의 딕셔너리입니다.
    """
    yara_rules = {}
    for filename in os.listdir(directory):
        if filename.endswith('.yar'):
            path = os.path.join(directory, filename)
            try:
                rule = yara.compile(filepath=path)
                # 파일 이름(확장자 제외)을 key로 사용
                key = os.path.splitext(filename)[0]
                yara_rules[key] = rule
                logging.info("Loaded YARA rule: %s", key)
            except Exception as e:
                logging.error("Failed to load %s: %s", filename, e)
    return yara_rules