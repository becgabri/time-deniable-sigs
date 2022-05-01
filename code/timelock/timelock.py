from charm.toolbox.integergroup import RSAGroup 
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
import time
from hashlib import sha256 # this is probably unnecessary :P 
import secrets

def extract_key(rsaElt):
    sha_hash = sha256()
    asInt = int(rsaElt)
    sha_hash.update(asInt.to_bytes(asInt.bit_length() + 7 // 8, 'big'))
    key_in_hex = sha_hash.digest().hex()
    return bytes(bytearray.fromhex(key_in_hex))    

# a^exp % n
# side channels here don't matter, the exponent isn't even private
def priv_exp(a, exp, n):
    exp_len = exp.bit_length()
    itr = a
    squares = [itr]
    for i in range(exp_len):
       itr = (itr * itr) % n
       squares.append(itr)
       
    exp_bin_repr = bin(exp)[2:][::-1]
    all_factors = [item[1] for item in zip(exp_bin_repr, squares) if item[0] == '1']
    accum = 1
    for factor in all_factors:
       accum = (accum * factor) % n
    return accum   

class TLP:
    def __init__(self, secs, sq_per_sec):
        # generate the parameters that you will use
        # specifically N 
        group = RSAGroup()
        p, q, n = group.paramgen(secparam=2048)
        self.phi = int(p-1) * int(q-1)
        self.n = int(n) 
        self.secs = secs
        self.sq_per_sec = sq_per_sec

    def encrypt(self, msg):

        random_a = secrets.randbelow(self.n)
        #print("random_a = {}".format(random_a))
        t = self.secs * self.sq_per_sec
        m = priv_exp(2, t, self.phi)
        #print("2^{} mod {} = {}".format(t, self.phi, m))
        res = priv_exp(random_a, int(m), self.n)
        #print("random_a ^ t = {}, mod n: {}".format(res, res % self.n)) 
        keyElt = secrets.randbelow(self.n)
        
        #print("Key element is {}, hard value is {}".format(keyElt, res)) 

        # note -- this is not aead, there is already nothing stopping the signer
        # from lying about this value (or the forger for that matter...)
        actual_key = extract_key(keyElt)
        ske = SymmetricCryptoAbstraction(actual_key)
        ct = ske.encrypt(msg)
        covered_key = (keyElt + res) % self.n
        return (t, self.n, random_a, ct, covered_key)

    def decrypt(self, t, n, a, ct, enc_key):
        #print("Inside decryption")
        total = a
        for i in range(t):
            total = total**2 % n
        #print("Hard value is {}".format(total))
        keyElt = (int(enc_key) - total) % n
        #print("Recovered key is {}".format(keyElt))
        actual_key = extract_key(keyElt)
        ske = SymmetricCryptoAbstraction(actual_key)
               
        return ske.decrypt(ct)

if __name__ == "__main__":
    # running very small scale tests 
    tlp = TLP(2, 2)
    input_txt = b"ackkkkkkkkkkkkkk"
    ct = tlp.encrypt(input_txt)
    pt = tlp.decrypt(ct[0], ct[1], ct[2], ct[3], ct[4])
    if input_txt != pt:
        print("Failed basic test :( ")
    else: 
        print("Passed simple test :) ")
