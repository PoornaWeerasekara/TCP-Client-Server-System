import socket

hostip = "127.0.0.1"
serverport = 50685

def sendmessage(sock, text):
    payload = text.encode()
    packet = f"LEN:{len(payload)}\n".encode() + payload
    sock.sendall(packet)

sock = socket.socket()
sock.connect((hostip, serverport))

print("Connected")

while True:
    cmd = input("Type REGISTER/LOGIN/LOGOUT <Username> <Password>  ")
    sendmessage(sock, cmd)
    print(sock.recv(4096).decode())
