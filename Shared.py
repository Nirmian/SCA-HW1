from Crypto.PublicKey import RSA

def get_pubkey_m():
    f = open("pubkey_m", "rb")
    pubkey_m = RSA.importKey(f.read())
    f.close()
    return pubkey_m

def get_pubkey_pg():
    f = open("pubkey_pg", "rb")
    pubkey_pg = RSA.importKey(f.read())
    f.close()
    return pubkey_pg