import os
import sys
import timeit
import time
from timelockpuzzle.algorithms.fast_exponentiation import fast_exponentiation
#from algorithms.fast_exponentiation import fast_exponentiation
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class TLP: 
    def __init__(self, secs, sq_per_sec):
        if not secs or not sq_per_sec:
            raise AssertionError

        # hard code safe exponent to use
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # see RSA for security specifications
        self.p, self.q = private_key.private_numbers().p, private_key.private_numbers().q
        self.n = private_key.public_key().public_numbers().n
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.sq_per_sec = sq_per_sec
        self.secs = secs
        

    def encrypt(self, message):
        # Fernet is an asymmetric encryption protocol using AES
        key = Fernet.generate_key()
        key_int = int.from_bytes(key, sys.byteorder)
        cipher_suite = Fernet(key)

        # Vote Encryption
        encrypted_message = cipher_suite.encrypt(message)

        # Pick safe, pseudo-random a where 1 < a < n
        # Alternatively, we could use a = 2
        a = int.from_bytes(os.urandom(32), sys.byteorder) % self.n + 1

        # Key Encryption
        t = self.secs * self.sq_per_sec
        e = fast_exponentiation(self.phi_n, 2, t)
        
        b = fast_exponentiation(self.n, a, e)

        encrypted_key = (key_int % self.n + b) % self.n
        return (t,  self.n, a, encrypted_message, encrypted_key)


    def decrypt(self, t:int, n: int, a: int, enc_message: int, enc_key: int) -> bytes:
        # Successive squaring to find b
        # We assume this cannot be parallelized
        b = a % self.n
        for i in range(t):
            b = b**2 % n
        dec_key = (enc_key - b) % self.n

        # Retrieve key, decrypt message
        key_bytes = int.to_bytes(dec_key, length=64, byteorder=sys.byteorder)
        cipher_suite = Fernet(key_bytes)
        return cipher_suite.decrypt(enc_message)


if __name__ == '__main__':
    median_list = []
    for i in range(500):
        beg_ticker = time.time() 
        TLP(1,3)
        duration = time.time() - beg_ticker
        median_list.append(duration)
    avg_t = sum(median_list) / len(median_list)
    midpt = len(median_list) // 2
    median_list.sort()
    print("TLP generation median: {}, average: {}".format(median_list[midpt],avg_t))
