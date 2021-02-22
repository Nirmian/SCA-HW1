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

class PaymentOrder:
    def __init__(self):
        self.body = {
            "orderdesc" : "",
            "sid" : 0,
            "amount" : 0,
            "nc" : 0,
            "sigc" : None
        }

class PaymentInformation:
    def __init__(self):
        self.body = {
           "cardn" : 0,
           "cardexp" : 0, 
           "ccode" : 0,
           "sid" : 0,
           "amount" : 0,
           "pubkc" : 0,
           "nc" : 0,
           "merchant" : 0
        }

class Card:
    def __init__(self):
        self.body = {
            "cardn" : 0,
            "cardexp" : 0,
            "ccode" : 0
        }
testcard = Card()
testcard.body["cardn"] = "1234567890123"
testcard.body["cardexp"] = "11/21"
testcard.body["cardcode"] = "321"