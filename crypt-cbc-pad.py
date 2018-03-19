from hashlib import md5
from base64 import b64decode, b64encode
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    """
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf8')


class BlowfishCipher:
    """
    Usage:
        c = BlowfishCipher('password').encrypt('message')
        m = BlowfishCipher('password').decrypt(c)
    """
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(Blowfish.block_size)
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:Blowfish.block_size]
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[Blowfish.block_size:])).decode('utf8')


if __name__ == "__main__":
    aes = AESCipher('password')
    blowfish = BlowfishCipher('password')

    e = aes.encrypt('msg')
    d = aes.decrypt(e)
    print "--AES--"
    print e
    print d

    e = blowfish.encrypt('msg')
    d = blowfish.decrypt(e)
    print '--Blowfish--'
    print e
    print d

