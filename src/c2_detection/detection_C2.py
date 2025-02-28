from scapy.all import sniff

# 탐지할 C2 서버 목록
C2_IPS = ["185.220.101.49", "203.0.113.45"]

# 패킷 캡처 후 분석
def packet_callback(packet):
    if packet.haslayer("IP"):
        if packet["IP"].dst in C2_IPS:
            print(f"[!] C2 connection detected: {packet['IP'].dst}")

sniff(filter="tcp", prn=packet_callback, store=0)
