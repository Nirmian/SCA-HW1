import socket
import bson
from AESFunctions import *
from Shared import *

private_key = RSA.generate(2048)
public_key = generate_to_file(private_key, 'keys/pubk_pg')

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        print("Starting Payment Gateway")
        server.bind(('127.0.0.1', PG_PORT))
        server.listen()
        while True:
            merchant, address = server.accept()
            print('Server listening on', ('127.0.0.1', PG_PORT))
            # receive PKC 
            data = merchant.recv(4096)
            data = bson.BSON.decode(data)

            pm = data['payment_message']
            sig_m = data['sigm']
            encrypted_aes_key = data['enc_k']
            decrypted_aes_key = rsa_decrypt_msg(encrypted_aes_key, private_key)

            # create & send signature to merchant
            # merchant.send(encrypted_key)