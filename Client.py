import socket
import json
import bson
from AESFunctions import *
from Crypto.PublicKey import RSA
from shared import *

# Generate public key of client
private_key = RSA.generate(2048)
public_key = private_key.publickey().exportKey()
pubk_m = None
pubk_pg = None
m_conn = None

# Send client public key to merchant
def setup_1():
    msg = hybrid_encrypt_msg(public_key, pubk_m)
    m_conn.send(bson.BSON.encode(msg))
    print('Succesfully sent pubk_c to m.')

# Receive response from merchant (Sid, SigM(Sid)) then return session id
def setup_2(info):
    encrypted_aes_key = info['enc_key']
    decrypted_aes_key = rsa_decrypt_msg(encrypted_aes_key, private_key)

    session_id = aes_decrypt_msg(decrypted_aes_key, info['session_id'])
    session_signature = aes_decrypt_msg(decrypted_aes_key, info['sid_signature'])

    if verify_signature(session_id, pubk_m, session_signature):
        print("valid signature")
    else:
        print("non-valid signature")
        m_conn.close()
    
    return session_id

def create_po(session_id):
    paymentorder = PaymentOrder()
    paymentorder.body["nonce"] = get_random_bytes(16)
    paymentorder.body["sid"] = session_id
    paymentorder.body["order_description"] = "Some test order"
    paymentorder.body["amount"] = 5
    return paymentorder

def create_pi(paymentorder):
    paymentinformation = PaymentInformation()
    paymentinformation.body["cardn"] = testcard.body["cardn"]
    paymentinformation.body["cardexp"] = testcard.body["cardexp"]
    paymentinformation.body["ccode"] = testcard.body["ccode"]
    paymentinformation.body["sid"] = session_id
    paymentinformation.body["amount"] = paymentorder.body["amount"]
    paymentinformation.body["pubkc"] = public_key
    paymentinformation.body["nonce"] = paymentorder.body["nonce"]
    paymentinformation.body["merchant"] = "some merchant"
    return paymentinformation

def create_pm_po(paymentorder, paymentinformation, pi_sig):
    k = get_random_bytes(16)
    encrypted_pi = aes_encrypt_msg(k, bson.encode({"pi": paymentinformation.body, "pi_sig": pi_sig}))
    encrypted_key = rsa_encrypt_msg(k, get_pubkey_pg())

    pm = {
        "enc_pi": encrypted_pi, 
        "enc_key": encrypted_key
    }

    #encrypt PM
    k = get_random_bytes(16)
    encrypted_pm_po = aes_encrypt_msg(k, bson.encode({"pm": pm, "po": paymentorder.body}))
    encrypted_pm_po_key = rsa_encrypt_msg(k, get_pubkey_m())

    return {
        "pm_po": encrypted_pm_po,
        "pm_po_key": encrypted_pm_po_key
    }

def exchange_3(session_id):
    paymentorder = create_po(session_id)
    #sign PO with private key
    po_sig = rsa_sign(paymentorder.get_encoded_info(), private_key)
    paymentorder.body["sigc"] = po_sig

    paymentinformation = create_pi(paymentorder)
    #sign PI
    pi_sig = rsa_sign(bson.encode(paymentinformation.body), private_key)

    #encrypt pm, po then send
    pm_po = create_pm_po(paymentorder, paymentinformation, pi_sig)
    m_conn.send(bson.encode(pm_po))

    return paymentinformation, paymentorder

def exchange_6(response, pi, session_id):
    decrypted_response = hybrid_decrypt_msg(bson.decode(response), private_key)
    decoded_response = bson.decode(decrypted_response["dec_text"])
    
    data_toverify = {
        "resp" : decoded_response["resp"],
        "sid" : session_id,
        "amount" : pi.body["amount"],
        "nonce" : pi.body["nonce"]
    }

    if decoded_response["sid"] == session_id:
        if verify_signature(bson.encode(data_toverify), get_pubkey_pg(), decoded_response["pg_sig"]):
            if decoded_response["resp"] == Response.OK:
                print("Transaction", session_id , "ACCEPTED!")
            else:
                print("Transaction", session_id , "REJECTED!")

if __name__ == "__main__":
    import time
    time.sleep(3)

    print("Starting Client.")
    m_conn = socket.socket()
    m_conn.connect(('127.0.0.1', M_PORT))
    
    pubk_m = get_pubkey_m()
    pubk_pg = get_pubkey_pg()

    # Setup subprotocol
    setup_1()

    response = m_conn.recv(4096)
    info = bson.decode(response)
    
    session_id = setup_2(info)

    #Exchange subprotocol
    pi, po = exchange_3(session_id)
    
    #6
    response = m_conn.recv(4096)
    print("Received response from M.")

    exchange_6(response, pi, session_id)