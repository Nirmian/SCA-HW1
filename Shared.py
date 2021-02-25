from Crypto.PublicKey import RSA
import bson

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

def get_msig_info(paymentinformation):
    return {
        "sid": paymentinformation["sid"],
        "amount": paymentinformation["amount"],
        "pubk_c": paymentinformation["pubkc"]
    }


class PaymentOrder:
    def __init__(self):
        self.body = {
            "orderdesc" : "",
            "sid" : 0,
            "amount" : 0,
            "nonce" : 0,
            "sigc" : None
        }

    #used so we don't include the signature property when signing PO
    def get_info_only(self):
        return {k:self.body[k] for k in self.body if k!='sigc'}

    def get_encoded_info(self):
        return bson.encode(self.get_info_only())

    def get_sigc(self):
        return self.body["sigc"]



class PaymentInformation:
    def __init__(self):
        self.body = {
           "cardn" : 0,
           "cardexp" : 0, 
           "ccode" : 0,
           "sid" : 0,
           "amount" : 0,
           "pubkc" : 0,
           "nonce" : 0,
           "merchant" : 0
        }
    

class Card:
    def __init__(self):
        self.body = {
            "cardn" : 0,
            "cardexp" : 0,
            "ccode" : 0
        }

class Response:
    OK = 100
    NOT_OK = 101

testcard = Card()
testcard.body["cardn"] = "1234567890123"
testcard.body["cardexp"] = "11/21"
testcard.body["cardcode"] = "321"