import socket
import json
import bson
from AESFunctions import *
from shared import *

private_key = RSA.generate(2048)
public_key = generate_to_file(private_key, 'keys/pubk_m')

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        print("Starting Merchant")
        server.bind(('127.0.0.1', M_PORT))
        server.listen()
        print('Server listening on', ('127.0.0.1', M_PORT))
        while True:
            client, address = server.accept()

            # receive PKC
            data = client.recv(4096)
            data = bson.BSON.decode(data)

            # create & send signature to Client
            data = hybrid_decrypt_msg(data, private_key)

            session_id = get_random_bytes(16)
            client_signature = compute_signature(session_id, private_key)

            k = get_random_bytes(16)
            encrypted_session_id = aes_encrypt_msg(k, session_id)
            encrypted_client_signature = aes_encrypt_msg(k, client_signature)
            encrypted_k = rsa_encrypt_msg(k, RSA.importKey(data['dec_text']))

            client.send(bson.BSON.encode(
                {
                    "session_id": encrypted_session_id,
                    "sid_signature": encrypted_client_signature,
                    "enc_key": encrypted_k
                }
            ))
