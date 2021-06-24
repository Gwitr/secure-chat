import os
import time
import socket
import threading
import rsa, pyaes, secrets

MAX_CLIENTS = 8
RSA_KEY_BITS = 2048  # Yeah I know it's insecure, but it's also fast

def server_handshake(connection, pub, priv, rsa_bits):
    """Does a handshake with a client. Returns the AES key and iv which should be used to decrypt
and encrypt everything sent. This function takes some time to execute and should be run in a
thread."""
    
    connection.settimeout(5)
    
    # Send challenge
    challenge = secrets.randbits(256)
    expected_response = (challenge ^ (challenge >> 11)).to_bytes(32, "big")
    challenge = challenge.to_bytes(32, "big")
    connection.sendall(challenge)

    # Receive response
    buf = b""
    try:
        while len(buf) != 32:
            data = connection.recv(32 - len(buf))
            if len(data) == 0:
                raise ConnectionAbortedError("Client has closed the connection.")
            buf += data
    
    except socket.timeout:
        connection.shutdown(socket.SHUT_RDWR)
        connection.close()
        raise ConnectionError("Client did not respond to the challenge in time.") from None
    
    if buf != expected_response:
        connection.shutdown(socket.SHUT_RDWR)
        connection.close()
        raise ConnectionError("Client did not respond to the challenge correctly.")
    
    # Send public key
    connection.sendall(pub.save_pkcs1() + b"\0")
    
    # Receive the AES iv and key
    buf = b""
    while len(buf) != rsa_bits // 8:
        data = connection.recv(rsa_bits // 8 - len(buf))
        if len(data) == 0:
            raise ConnectionAbortedError("Client has closed the connection.")
        buf += data
    
    raw_data = rsa.decrypt(buf, priv)
    iv = int.from_bytes(raw_data[:32], "big")
    key = raw_data[32:]
    return key, iv

def client_send_thread(chat_buffer, conn, aes_out, over):
    try:
        last_pos = 0
        while not over[0]:
            while last_pos < len(chat_buffer):
                msg = aes_out.encrypt(chat_buffer[last_pos].encode("utf8"))
                conn.sendall(len(msg).to_bytes(4, "big") + msg)
                last_pos += 1
            time.sleep(.1)
    
    finally:
        print("client send thread over")

def client_thread(chat_buffer, client_threads, conn, ip, pub, priv, rsa_bits):
    over = [False]
    try:
        key, iv = server_handshake(conn, pub, priv, rsa_bits)
        conn.settimeout(None)
        
        aes_in = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        aes_out = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
        
        length = int.from_bytes(conn.recv(4), "big")
        username = conn.recv(length)
        username = aes_in.decrypt(username).decode("utf8")
        
        chat_buffer.append(username + " has connected")
        
        th = threading.Thread(target=client_send_thread, args=(chat_buffer, conn, aes_out, over))
        th.daemon = True
        th.start()
        while 1:
            length = int.from_bytes(conn.recv(4), "big")
            message = conn.recv(length)
            message = aes_in.decrypt(message)
            message = "%s: %s" % (username, message.decode("utf8"))
            print(message)
            chat_buffer.append(message)
    
    finally:
        print(ip, "disconnected")
        client_threads.remove(threading.current_thread())
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        over[0] = True
        chat_buffer.append(username + " has disconnected")

if __name__ == "__main__":
    print("Generating public / private key pair")
    pub, priv = rsa.newkeys(RSA_KEY_BITS)

    print("Starting server")
    s = socket.socket()
    s.bind(("0.0.0.0", 30000))
    s.listen(1)
    
    chat_buffer = []
    client_threads = set()
    while 1:
        conn, ip = s.accept()
        print(ip, "connected")
        thread = threading.Thread(target=client_thread, args=(chat_buffer, client_threads, conn, ip, pub, priv, RSA_KEY_BITS))
        thread.daemon = True
        thread.start()
        
        client_threads.add(thread)
        if len(client_threads) > MAX_CLIENTS:
            print("Client limit reached")
            while len(client_threads) > MAX_CLIENTS:
                time.sleep(.1)

