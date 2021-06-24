# pip3 install rsa pyaes

import os
import sys
import socket
import rsa, pyaes, secrets
from threading import Thread

def client_handshake(connection, key, iv):
    """Does a handshake with the server."""
    
    connection.settimeout(5)
    
    # Receive challenge
    buf = b""
    while len(buf) != 32:
        data = connection.recv(32 - len(buf))
        if len(data) == 0:
            raise ConnectionAbortedError("Server has closed the connection.")
        buf += data
    
    # Respond to the challenge
    challenge = int.from_bytes(buf, "big")
    response = challenge ^ (challenge >> 11)
    connection.sendall(response.to_bytes(32, "big"))
    
    # Receive public key
    buf = b""
    while buf[-1:] != b"\0":
        data = connection.recv(1)
        if len(data) == 0:
            raise ConnectionAbortedError("Server has closed the connection.")
        buf += data
    pub = rsa.PublicKey.load_pkcs1(buf[:-1])
    
    # Send the AES iv and key
    data = rsa.encrypt(iv.to_bytes(32, "big") + key, pub)
    connection.sendall(data)

def print_thread(connection, aes_in):
    connection.settimeout(None)
    
    while 1:
        length = connection.recv(4)
        if length == b"":
            raise ConnectionAbortedError
        length = int.from_bytes(length, "big")
        
        encrypted = connection.recv(length)
        text = aes_in.decrypt(encrypted)
        print(text.decode("utf8"))

HOST, PORT = "192.168.1.31", 30000
if __name__ == "__main__":
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    
    iv = secrets.randbits(256)
    key = secrets.randbits(256).to_bytes(256 // 8, "big")
    aes_in = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    aes_out = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    
    connection = socket.create_connection((HOST, PORT))
    client_handshake(connection, key, iv)
    
    username = input("Username: ")
    username = aes_out.encrypt(username.encode("utf8"))
    connection.sendall(len(username).to_bytes(4, "big") + username)
    t = Thread(target=print_thread, args=(connection, aes_in))
    t.daemon = True
    t.start()
    while 1:
        message = input("")
        sys.stdout.buffer.write(b"\033[F")
        message = aes_out.encrypt(message.encode("utf8"))
        connection.sendall(len(message).to_bytes(4, "big") + message)
