import socket
from AESFunctions import *
from shared import *

private_key = RSA.generate(2048)
public_key = generate_to_file(private_key, 'keys/pubk_pg')

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        print("Starting Merchant")
        server.bind(('127.0.0.1', PG_PORT))
        server.listen()
        while True:
            client, address = server.accept()
            print('Server listening on', ('127.0.0.1', PG_PORT))
            # receive PKC 
            data = client.recv(1024).decode()
            encrypted_key = b''

            # create & send signature to Client
            client.send(encrypted_key)