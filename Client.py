import socket
import json
import bson
from AESFunctions import *
from Crypto.PublicKey import RSA
from shared import *

# Generate public key of client
private_key = RSA.generate(2048)
public_key = private_key.publickey().exportKey()

if __name__ == "__main__":
    print("Starting Client.")
    
    pubk_m = get_pubkey_m()
    pubk_pg = get_pubkey_pg()

    # Setup subprotocol

    msg = hybrid_encrypt_msg(public_key, pubk_m)

    # Send client public key to merchant
    m_conn = socket.socket()
    m_conn.connect(('127.0.0.1', M_PORT))
    m_conn.send(bson.BSON.encode(msg))
    print('Succesfully sent pubk_c to m.')

    # Received response from merchant (Sid, SigM(Sid))
    response = m_conn.recv(2048)
    info = bson.BSON.decode(response)

    encrypted_aes_key = info['enc_key']
    decrypted_aes_key = rsa_decrypt_msg(encrypted_aes_key, private_key)

    session_id = aes_decrypt_msg(decrypted_aes_key, info['session_id'])
    session_signature = aes_decrypt_msg(decrypted_aes_key, info['sid_signature'])

    if verify_signature(session_id, pubk_m, session_signature):
        print("valid signature")
    else:
        print("non-valid signature")
        m_conn.close()