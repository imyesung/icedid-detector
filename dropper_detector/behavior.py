import os

class BehaviorAnalyzer:
    def __init__(self):
        self.malicious_patterns = {
            'file_operations': ['open(', 'write(', 'os.remove', 'os.mkdir'],
            'system_operations': ['os.system', 'subprocess', 'exec(', 'eval('],
            'network_operations': ['socket.socket', 'urllib.request', 'http.client']
        }

    def analyze(self, file_path):
        results = {"file_path": file_path, "suspicious_activities": []}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            for category, patterns in self.malicious_patterns.items():
                for pattern in patterns:
                    if pattern in content:
                        results['suspicious_activities'].append({
                            'category': category,
                            'pattern': pattern
                        })
        except Exception as e:
            results['error'] = str(e)
        return results