from base64 import b64decode, b64encode
from Crypto.Cipher import Blowfish
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * '\0'

class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message', 'iv')
        m = AESCipher('password').decrypt(c, 'iv')
        # iv 8 byte
    """

    def __init__(self, key, iv):
        self.key = key
	self.iv = iv

    def encrypt(self, raw):
        cipher = AES.new(b64decode(self.key), AES.MODE_CBC, self.iv)
        return b64encode(cipher.encrypt(pad(raw).encode('utf-8')))

    def decrypt(self, enc):
        cipher = AES.new(b64decode(self.key), AES.MODE_CBC, self.iv)
        return cipher.decrypt(b64decode(enc)).decode('utf8')


class BlowfishCipher:
    """
    Usage:
        c = BlowfishCipher('password').encrypt('message', 'iv')
        m = BlowfishCipher('password').decrypt(c, 'iv')
        # iv 8 byte
    """

    def __init__(self, key, iv):
        self.key = key
	self.iv = iv

    def encrypt(self, raw):
        cipher = Blowfish.new(b64decode(self.key), Blowfish.MODE_CBC, self.iv)
        return b64encode(cipher.encrypt(pad(raw).encode('utf-8')))

    def decrypt(self, enc):
        cipher = Blowfish.new(b64decode(self.key), Blowfish.MODE_CBC, self.iv)
        return cipher.decrypt(b64decode(enc)).decode('utf8')


if __name__ == "__main__":
    aes = AESCipher('aaaabbbbccccdddd1111222233334444', '0000000000000000')
    blowfish = BlowfishCipher('aabbccdd', '00000000')

    e = aes.encrypt('msg')
    d = aes.decrypt(e)
    print "--AES--"
    print e
    print d

    e = blowfish.encrypt('msg')
    d = blowfish.decrypt(e)
    print "\n--Blowfish--"
    print e
    print d
