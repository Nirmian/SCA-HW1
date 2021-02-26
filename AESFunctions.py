# encrypt and decrypt from https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# signature methods from https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html#Crypto.Signature.pkcs1_15.new
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

BLOCK_SIZE = 16

def padding(text, bl_size):
    if(len(text) % bl_size != 0):
        if isinstance(text, (bytes  , bytearray)):
            text = text.decode("utf-8")
        padding_length =  bl_size - len(text) % bl_size
        text = text + padding_length * chr(0)
    if isinstance(text, bytes):
        return text
    else:
        return text.encode("utf-8")

def string_xor(s1, s2):
    return bytes([_a ^ _b for _a, _b in zip(s1, s2)])

def hybrid_encrypt_msg(text, key):
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted_text_rsa = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    encrypted_text_k = cipher_aes.encrypt(pad(text, BLOCK_SIZE))

    info = {
        "enc_key" : encrypted_text_rsa,
        "enc_text" : encrypted_text_k
    }
    return info

def hybrid_decrypt_msg(info, decrypt_key, dict_keyname="enc_key", dict_textname="enc_text"):  
    cipher_rsa = PKCS1_OAEP.new(decrypt_key)
    decrypted_text_rsa = cipher_rsa.decrypt(info[dict_keyname])

    cipher_rsa = AES.new(decrypted_text_rsa, AES.MODE_ECB)
    decrypted_text_k = unpad(cipher_rsa.decrypt(info[dict_textname]), BLOCK_SIZE)

    info = {
        "dec_key" : decrypted_text_rsa,
        "dec_text" : decrypted_text_k
    }
    return info

def rsa_encrypt_msg(key, rsa_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_msg_rsa = cipher_rsa.encrypt(key)
    return encrypted_msg_rsa

def rsa_decrypt_msg(key, rsa_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_msg_rsa = cipher_rsa.decrypt(key)
    return decrypted_msg_rsa

def aes_encrypt_msg(key, msg):
    cipher_aes = AES.new(key, AES.MODE_ECB)
    encrypted_text_k = cipher_aes.encrypt(pad(msg, BLOCK_SIZE))
    return encrypted_text_k

def aes_decrypt_msg(key, msg):
    cipher_aes = AES.new(key, AES.MODE_ECB)
    decrypted_text_k = unpad(cipher_aes.decrypt(msg), BLOCK_SIZE)
    return decrypted_text_k

def compute_signature(msg, private_key):
    h = SHA256.new(msg)
    return pkcs1_15.new(private_key).sign(h)

def verify_signature(data, public_key, signature):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def generate_to_file(private_key, path):
    pubkm = private_key.publickey()
    with open(path, "wb") as f:
        f.write(pubkm.exportKey('PEM'))
    print("Generated public key")
    return pubkm

def rsa_sign(data, private_key):
    digest = SHA256.new() 
    digest.update(data) #h(data)
    return pkcs1_15.new(private_key).sign(digest) #SigPvK(data)