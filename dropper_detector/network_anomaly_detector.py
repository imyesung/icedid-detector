import re

class NetworkMonitor:
    def __init__(self):
        self.ioc_list = {  # IOC(Indicators of Compromise)
            "malicious_ips": ["192.168.1.100", "8.8.8.8"],
            "malicious_domains": ["malware-site.com", "phishing-site.org"]
        }

    def analyze(self, file_path):
        results = {"file_path": file_path, "network_alerts": []}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            for ip in self.ioc_list["malicious_ips"]:
                if ip in content:
                    results['network_alerts'].append({"type": "malicious_ip", "value": ip})
            for domain in self.ioc_list["malicious_domains"]:
                if domain in content:
                    results['network_alerts'].append({"type": "malicious_domain", "value": domain})
        except Exception as e:
            results['error'] = str(e)
        return results