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
        self.orderdesc = ""
        self.sid = 0
        self.amount = 0
        self.nc = 0
        self.sigc = None

class PaymentInformation:
    def __init__(self):
        self.cardn = 0
        self.cardexp = 0 
        self.ccode = 0
        self.sid = 0
        self.amount = 0
        self.pubkc = 0
        self.nc = 0
        self.merchant = 0

class Card:
    def __init__(self):
        self.cardn = 0
        self.cardexp = 0
        self.ccode = 0

testcard = Card()
testcard.cardn = "1234567890123"
testcard.cardexp = "11/21"
testcard.cardcode = "321"