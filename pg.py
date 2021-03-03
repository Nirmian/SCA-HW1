import socket
import bson
from AESFunctions import *
from shared import *

private_key = RSA.generate(2048)
public_key = generate_to_file(private_key, 'keys/pubk_pg')
m_conn = None
cards = {
    '1234567890123' : {'cardexp': '11/21', 'ccode': '0', 'amount' : 5}
}

def verify_pm_msig_pi_pisig(data, pubk_m):
    decrypted_pm_msig = hybrid_decrypt_msg(data, private_key)
    pm_msig = bson.decode(decrypted_pm_msig["dec_text"])
    msig = pm_msig["m_sig"]
    decrypted_pi_pisig = hybrid_decrypt_msg(pm_msig["pm"], private_key)

    pi_pisig = bson.decode(decrypted_pi_pisig["dec_text"])
    pi = pi_pisig["pi"]
    
    print("Transaction:", pi['sid'])

    if verify_signature(bson.encode(get_msig_info(pi)), pubk_m, msig):
        print("PM, Merchant Sig OK!")
    
    if verify_signature(bson.encode(pi), RSA.import_key(pi["pubkc"]), pi_pisig["pi_sig"]):
        print("PI, Client Sig OK!")
    return pi

def exchange_4(data, pubk_m):
    response = Response.OK
    pi = verify_pm_msig_pi_pisig(data, pubk_m)
    if pi['amount'] <= cards[pi['cardn']]['amount']:
        print('Client has the required amount')
    else:
        print('Client does not have the required amount')
        response = Response.NOT_OK
    return pi, response
    #needs to check card balance or something

def exchange_5(resp, pi, pubk_m):
    pg_sig = compute_signature(
        bson.encode({
            "resp": resp,
            "sid": pi["sid"],
            "amount": pi["amount"],
            "nonce": pi["nonce"]
        }),
        private_key
        )
    response = bson.encode(
        {
            "resp": resp,
            "sid": pi["sid"],
            "pg_sig": pg_sig
        }
    )
    m_conn.send(bson.encode(hybrid_encrypt_msg(response, pubk_m)))
    print('Transaction response:', 'ACCEPTED' if resp == Response.OK else 'REJECTED')
    print('Sending transaction response to merchant')

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        print("Starting Payment Gateway")
        server.bind(('127.0.0.1', PG_PORT))
        server.listen()
        while True:
            m_conn, address = server.accept()
            print('Server listening on', ('127.0.0.1', PG_PORT))
            pubk_m = get_pubkey_m()

            # Exchange step 4
            #receive PM, SigM(Sid, pubkc, amount)
            data = m_conn.recv(4096)
            data = bson.decode(data)

            pi, response = exchange_4(data, pubk_m)

            #step 5
            exchange_5(response, pi, pubk_m)
            

            
            
            
            
            

            
            