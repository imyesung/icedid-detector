from scapy.all import sniff

# 탐지할 C2 서버 목록
C2_IPS = ["192.168.1.10", "45.83.55.67"]

# 패킷 캡처 후 분석
def packet_callback(packet):
    if packet.haslayer("IP"):
        if packet["IP"].dst in C2_IPS:
            print(f"[!] C2 connection detected: {packet['IP'].dst}")

sniff(filter="tcp", prn=packet_callback, store=0)
