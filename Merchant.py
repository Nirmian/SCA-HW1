import socket
import json
import bson
from AESFunctions import *
from shared import *

private_key = RSA.generate(2048)
public_key = generate_to_file(private_key, 'keys/pubk_m')
client_conn = None
pg_conn = None

#Create & send signature to client_conn
def setup_2(data):
    data = hybrid_decrypt_msg(data, private_key, "enc_key", "enc_text")
    client_pubk = data["dec_text"]

    session_id = get_random_bytes(16)
    client_conn_signature = compute_signature(session_id, private_key)

    k = get_random_bytes(16)
    encrypted_session_id = aes_encrypt_msg(k, session_id)
    encrypted_client_conn_signature = aes_encrypt_msg(k, client_conn_signature)
    encrypted_k = rsa_encrypt_msg(k, RSA.importKey(client_pubk)) # Rename this to rsa_client_key

    client_conn.send(bson.encode(
        {
            "session_id": encrypted_session_id,
            "sid_signature": encrypted_client_conn_signature,
            "enc_key": encrypted_k
        }
    ))

    return (client_pubk, session_id)

#Receive PM, PO, verify signature
def exchange_3(data):
    #decrypt msg
    pm_po_key = rsa_decrypt_msg(data["pm_po_key"], private_key)
    pm_po = aes_decrypt_msg(pm_po_key, data["pm_po"])
    #load using bson
    loaded_pm_po = bson.decode(pm_po)
    pm = loaded_pm_po["pm"]
    po = PaymentOrder()
    po.body = loaded_pm_po["po"]
    
    if verify_signature(po.get_encoded_info(), RSA.import_key(client_pubk), po.body["sigc"]):
        print("Order signature OK!")
    
    return pm, po

#Send PM, SigM(Sid, PubKC, Amount)
def exchange_4(pm, po):
    m_sig = rsa_sign(
        bson.encode({
            "sid": po.body["sid"],
            "amount": po.body["amount"],
            "pubk_c": client_pubk
            }),
        private_key
        )
    k = get_random_bytes(16)
    encrypted_pm = aes_encrypt_msg(k, bson.encode(
        {
            "pm": pm,
            "m_sig": m_sig
        }
    ))
    encrypted_pm_k = rsa_encrypt_msg(k, get_pubkey_pg())
    pg_conn.send(bson.encode(
        {
            "enc_pm": encrypted_pm,
            "enc_pm_k": encrypted_pm_k
        }
    ))
    print('Succesfully sent payment message to PG')

def exchange_5(resp):
    decrypted_resp = hybrid_decrypt_msg(resp, private_key, "enc_key", "enc_text")
    decrypted_resp = bson.decode(decrypted_resp['dec_text'])

    print('Received response from PG')
    return decrypted_resp

def exchange_6(decrypted_resp, sid, po, client_pubk):
    sig_pg = bson.encode(
        {
            "resp": decrypted_resp['resp'],
            "sid": decrypted_resp['sid'],
            "amount": po.body['amount'],
            "nonce": po.body['nonce']
        }
    )
    if sid == decrypted_resp['sid']:
        if verify_signature(sig_pg, get_pubkey_pg(), decrypted_resp['pg_sig']):
            data = hybrid_encrypt_msg(bson.encode(decrypted_resp), RSA.importKey(client_pubk))
            client_conn.send(bson.encode(data))

if __name__ == "__main__":
    import time
    time.sleep(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        print("Starting Merchant")
        server.bind(('127.0.0.1', M_PORT))
        server.listen()
        print('Server listening on', ('127.0.0.1', M_PORT))
        while True:
            client_conn, address = server.accept()

            # Setup subprotocol
            # setup 1 receive encrypted PKC
            data = client_conn.recv(4096)
            data = bson.decode(data)

            client_pubk, session_id = setup_2(data)
            
            #Exchange subprotocol
            data = client_conn.recv(4096)
            data = bson.decode(data)

            pm, po = exchange_3(data)

            #4 Connect to PG 
            pg_conn = socket.socket()
            pg_conn.connect(('127.0.0.1', PG_PORT))
            
            exchange_4(pm, po)

            #5 Receive response from PG
            data = pg_conn.recv(4096)
            data = bson.decode(data)
            decrypted_resp = exchange_5(data)

            #6 Verify pg_sig and session id
            exchange_6(decrypted_resp, session_id, po, client_pubk)
