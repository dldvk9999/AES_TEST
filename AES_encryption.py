from Crypto import Random
from Crypto.Cipher import AES
import time
import base64
import hashlib

data = "TEST+_)(TEST"
# key = [0x10, 0x01, 0x15, 0x1B, 0xA1, 0x11, 0x57, 0x72, 0x6C, 0x21, 0x56, 0x57, 0x62, 0x16, 0x05, 0x3D,
#        0xFF, 0xFE, 0x11, 0x1B, 0x21, 0x31, 0x57, 0x72, 0x6B, 0x21, 0xA6, 0xA7, 0x6E, 0xE6, 0xE5, 0x3F]
print("Original Data :\t", data)


def make_pass():
    print("time :\t", int(time.time()))
    timekey = int(time.time())
    return str(timekey)


password = make_pass().encode()
ENC_key = hashlib.sha256(password).digest()
print("ENC_Key :\t", ENC_key)

BS = 16
pad = lambda s: s + (BS - len(s.encode('utf-8')) % BS) * chr(BS - len(s.encode('utf-8')) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode('utf-8')))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


encrypted_data = AESCipher(bytes(ENC_key)).encrypt(data)
print("ENC_Data :\t", encrypted_data.decode())


temp = int(time.time())
decrypted_data = ""
for i in range(temp - 1000, temp + 1000):
    print("\rCrack KEY : " + str(i), end="")
    decrypted_data = AESCipher(bytes(hashlib.sha256(str(i).encode()).digest())).decrypt(encrypted_data)
    try:
        if decrypted_data.decode():
            print("\t==>\t", decrypted_data.decode())
    except Exception:
        pass

# print("\nDEC_Data :\t", decrypted_data.decode())
