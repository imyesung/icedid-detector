import os
import sys
import ast
import json
from static_hash_detection import SignatureDetector
from file_behavior_analysis import BehaviorAnalyzer
from network_anomaly_detector import NetworkMonitor


class AdvancedMalwareDetector:
    def __init__(self):
        self.detector = SignatureDetector()
        self.behavior = BehaviorAnalyzer()
        self.network = NetworkMonitor()

    def analyze_ast(self, file_path):
        results = {"file_path": file_path, "suspicious_code": []}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in ["eval", "exec", "compile", "os.system", "subprocess.Popen", "subprocess.run"]:
                        results['suspicious_code'].append(func_name)
        except Exception as e:
            results['error'] = str(e)
        return results

    def evaluate_risk(self, sig_result, bhv_result, net_result, ast_result):
        base_score = 0
        weight_factors = {
            "signature": 50 if sig_result["detected"] else 0,
            "behavior": len(bhv_result["suspicious_activities"]) * 10,
            "network": len(net_result["network_alerts"]) * 15,
            "ast": len(ast_result["suspicious_code"]) * 20
        }
        total_score = sum(weight_factors.values())
        risk_level = "Low"
        if total_score >= 50:
            risk_level = "Medium"
        if total_score >= 80:
            risk_level = "High"
        if total_score > 100:
            risk_level = "Critical"
        return {"score": min(total_score, 100), "risk_level": risk_level}

    def analyze(self, file_path):
        sig_result = self.detector.analyze(file_path)
        bhv_result = self.behavior.analyze(file_path)
        net_result = self.network.analyze(file_path)
        ast_result = self.analyze_ast(file_path)
        risk_evaluation = self.evaluate_risk(sig_result, bhv_result, net_result, ast_result)
        return {
            "signature_analysis": sig_result,
            "behavior_analysis": bhv_result,
            "network_analysis": net_result,
            "ast_analysis": ast_result,
            "risk_evaluation": risk_evaluation
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[!] 사용법: python dropper_main.py <파일_경로>")
        sys.exit(1)
    detector = AdvancedMalwareDetector()
    result = detector.analyze(sys.argv[1])
    print("\n[+] 최종 분석 결과:")
    print(json.dumps(result, indent=4, ensure_ascii=False))