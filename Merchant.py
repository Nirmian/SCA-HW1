import socket
from AESFunctions import *

PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    print("Starting Merchant")
    server.bind(('127.0.0.1', PORT))
    server.listen()
    while True:
        client, address = server.accept()
        print('Server listening on', ('127.0.0.1', PORT))
        # receive PKC 
        data = client.recv(1024).decode()
        encrypted_key = b''

        # create & send signature to Client
        client.send(encrypted_key)