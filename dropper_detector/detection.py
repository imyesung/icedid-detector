import hashlib

class SignatureDetector:
    def __init__(self):
        self.signatures = {
            "malware1": "e1a010fcdcb8ef76b91c9b4d8ada0124",
            "malware2": "f2b8e8c8e8c8e8c8e8c8e8c8e8c8e8c8"
        }

    def get_file_hash(self, file_path):
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def analyze(self, file_path):
        file_hash = self.get_file_hash(file_path)
        for malware_name, signature in self.signatures.items():
            if file_hash == signature:
                return {"detected": True, "malware_name": malware_name}
        return {"detected": False}