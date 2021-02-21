from Crypto.PublicKey import RSA

C_PORT = 65430
M_PORT = 65431
PG_PORT = 65432

def get_pubkey_m():
    f = open("keys/pubk_m", "rb")
    pubkey_m = RSA.importKey(f.read())
    f.close()
    return pubkey_m

def get_pubkey_pg():
    f = open("keys/pubk_pg", "rb")
    pubkey_pg = RSA.importKey(f.read())
    f.close()
    return pubkey_pg