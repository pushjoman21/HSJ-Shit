from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

FP_KEY = bytes.fromhex("fe1ba43f33813dbac034ef12f34f3ee371b09057e2a25346a652c681edb2104b")

RESPONSE_KEY = bytes.fromhex("2fb5e0f6aab9596b2001c45ce12cad34e82d579dfea24409fe9b7de4b82d4028")

def _encrypt(data, key):
    iv = get_random_bytes(12)
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    d = data.encode() if isinstance(data, str) else data
    ct, tag = cipher.encrypt_and_digest(d)
    # format: ciphertext + tag(16) + iv(12) + 0x00
    return ct + tag + iv + b"\x00"


def _decrypt(raw, key):
    if isinstance(raw, str):
        raw = raw.encode()
    ct, tag, iv = raw[:-29], raw[-29:-13], raw[-13:-1]
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)


def encrypt(data):
    return base64.b64encode(_encrypt(data, FP_KEY))


def encrypt_raw(data):
    return _encrypt(data, FP_KEY)


def decrypt(b64_data):
    return _decrypt(base64.b64decode(b64_data), FP_KEY)


def decrypt_raw(raw):
    return _decrypt(raw, FP_KEY)


def encrypt_response(data):
    return base64.b64encode(_encrypt(data, RESPONSE_KEY))


def encrypt_response_raw(data):
    return _encrypt(data, RESPONSE_KEY)


def decrypt_response(b64_data):
    return _decrypt(base64.b64decode(b64_data), RESPONSE_KEY)


def decrypt_response_raw(raw):
    return _decrypt(raw, RESPONSE_KEY)
