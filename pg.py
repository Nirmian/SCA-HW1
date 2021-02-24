import socket
import bson
from AESFunctions import *
from shared import *

private_key = RSA.generate(2048)
public_key = generate_to_file(private_key, 'keys/pubk_pg')

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        print("Starting Payment Gateway")
        server.bind(('127.0.0.1', PG_PORT))
        server.listen()
        while True:
            m_conn, address = server.accept()
            print('Server listening on', ('127.0.0.1', PG_PORT))
            # Exchange step 4

            #receive PM, SigM(Sid, pubkc, amount)
            data = m_conn.recv(4096)
            data = bson.decode(data)

            #decrypted_pm_msig_key = rsa_decrypt_msg(data["enc_pm_k"], private_key)
            #decrypted_pm_msig = aes_decrypt_msg(decrypted_pm_msig_key, data["enc_pm"])

            decrypted_pm_msig = hybrid_decrypt_msg(data, private_key, "enc_pm_k", "enc_pm")



            pm_msig = bson.decode(decrypted_pm_msig["dec_text"])
            #decrypted_pi_key = rsa_decrypt_msg(pm_msig["pm"]["enc_key"], private_key)
            #decrypted_pi = aes_decrypt_msg(decrypted_pi_key, pm_msig["pm"]["enc_pi"])
            decrypted_pi = hybrid_decrypt_msg(pm_msig["pm"], private_key, "enc_key", "enc_pi")

            print(decrypted_pi)