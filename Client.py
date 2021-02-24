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
    import time
    time.sleep(3)

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
    response = m_conn.recv(4096)
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
    
    #Exchange subprotocol

    paymentorder = PaymentOrder()
    paymentorder.body["nonce"] = get_random_bytes(16)
    paymentorder.body["sid"] = session_id
    paymentorder.body["order_description"] = "Some test order"
    paymentorder.body["amount"] = 5
    #sign PO with private key

    po_sig = rsa_sign(paymentorder.get_encoded_info(), private_key)

    paymentorder.body["sigc"] = po_sig

    #create PI
    paymentinformation = PaymentInformation()
    paymentinformation.body["cardn"] = testcard.body["cardn"]
    paymentinformation.body["cardexp"] = testcard.body["cardexp"]
    paymentinformation.body["ccode"] = testcard.body["ccode"]
    paymentinformation.body["sid"] = session_id
    paymentinformation.body["amount"] = paymentorder.body["amount"]
    paymentinformation.body["pubkc"] = public_key
    paymentinformation.body["nc"] = paymentorder.body["nc"]
    paymentinformation.body["merchant"] = "some merchant"

    #sign PI
    pi_sig = rsa_sign(bson.encode(paymentinformation.body), private_key)

    #create PM
    k = get_random_bytes(16)
    encrypted_pi = aes_encrypt_msg(k, bson.encode({"pi": paymentinformation.body, "pi_sig": pi_sig}))
    encrypted_key = rsa_encrypt_msg(k, get_pubkey_pg())

    pm = {
        "enc_pi": encrypted_pi, 
        "enc_key": encrypted_key
    }

    #encrypt PM then send
    k = get_random_bytes(16)
    encrypted_pm_po = aes_encrypt_msg(k, bson.encode({"pm": pm, "po": paymentorder.body}))
    encrypted_pm_po_key = rsa_encrypt_msg(k, get_pubkey_m())

    m_conn.send(bson.encode({
        "pm_po": encrypted_pm_po,
        "pm_po_key": encrypted_pm_po_key
    })
    )

    #6
    response = m_conn.recv(4096)