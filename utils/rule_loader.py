# utils/rule_loader.py
import os
import logging
import yara

def load_yara_rules_from_directory(directory: str) -> dict:
    """
    지정된 디렉토리에서 모든 .yar 파일을 로드하고, 파일명(확장자 제거)을 키로 하는 딕셔너리를 반환합니다.
    """
    rules = {}
    for filename in os.listdir(directory):
        if filename.endswith(".yar"):
            path = os.path.join(directory, filename)
            try:
                compiled_rule = yara.compile(filepath=path)
                key = filename.rsplit(".", 1)[0]
                rules[key] = compiled_rule
                logging.info("Loaded YARA rule: %s", key)
            except Exception as e:
                logging.error("Error loading YARA rule %s: %s", filename, e)
    return rules