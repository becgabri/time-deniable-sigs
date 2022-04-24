
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, H, hashPair

from charm.core.math.integer import integer

class HIDE_GS:
    # the constructor
    def __init__(self):
        self.group = PairingGroup('BN254')
        return

    # output - tuple (master secret key, public params)
    def setup(self):
        # choose generator, of G_1 and secret exponent
        # BN 254, G_1 is prime order group, anything is a generator sans the identity
        self.P0 = self.group.random(G2)
        sk = self.group.random(ZR)
        PP = {"Q0": self.P0**sk, "P0": self.P0}
        MSK = {"s0": sk}
        return (MSK, PP)
     
    # input - I is a list of identity components, MSK the master secret key, PP the public params
    # output - secret key corresponding to I
    def keyGen(self, I, MSK, PP):
        S_t = self.group.init(G1, 0)
        t = len(I)
        QVals = []
        for i in range(t):
            # this would be dangerous if you allowed arbitrary length strings with arbitrary values
            P_i_plus_one = self.hashOntoG1(I[:i+1]) 
            s_i = self.group.random(ZR)
            if i == 0:
                s_i = MSK["s0"]
            else:  
                QVals.append(PP["P0"]**s_i)

            S_t = S_t + P_i_plus_one**s_i
        SK = {"S": S_t, "QVals": QVals}
        return SK

    # input - PP public params, SK a secret key from keyGen with identity I', I the identity you want to extract a key for where I' is a prefix of I
    # output - secret key corresponding to I
    def delegate(self, PP, SK, I):
        # prefix length *of the keys* always has len(Q) = len(I') - 1 bc we assume for a key len(I') = t, s_t for depth t is always produced "on the fly"
        prefix_len = len(SK["QVals"])

        S_prime = SK["S"]
        Q_prime = []
        # re-randomize earlier components for privacy
        for i in range(prefix_len):
            s_prime = self.group.random(ZR)
            Q_prime.append(SK["QVals"][i]+PP["P0"]**s_prime)
            id_elt = self.hashOntoG1(I[:i+2])
            S_prime += id_elt**s_prime
        
        # new components - prefix_len + 1 = t so this starts at t+1 
        for j in range(prefix_len+2, len(I)+1):
            # pick your exponent for this level
            s = self.group.random(ZR)
            Q = PP["P0"]**s
            Q_prime.append(Q)

            P_j = self.hashOntoG1(I[:j])
            S_prime += P_j**s
            
        return {"S": S_prime, "QVals":Q_prime}

    # input - M is a message, I is the identity you want to encrypt to, and PP the public params
    # output - ciphertext 
    def encrypt(self, M, I, PP):
        id_val = self.hashOntoG1(I)
        
        # random exponent for encryption
        r = self.group.random(ZR)
        PVals = [PP["P0"]**r]
        P1 = self.hashOntoG1([I[0]])
        
        for i in range(2,len(I)+1):
            temp = self.hashOntoG1(I[:i])
            PVals.append(temp**r)
        # need a hash funct. here onto message space
        # TODO:do real XOR  
        hash_key = hashPair(self.group.pair_prod([P1], [PP["Q0"]])**r)
        key_int_stream = [hash_key[i] ^ M[i] for i in range(len(hash_key))]
        C = bytes(key_int_stream)  
        return {"U": PVals, "C":C }

    # input - CT the ciphertext and SK the secret key to decrypt 
    # output - a message M corresponding to the CT 
    def decrypt(self, CT, SK):
        us = CT["U"][1:]
        key_elt = self.group.pair_prod([SK["S"]], [CT["U"][0]])
        # side channel for ID length
        if len(SK["QVals"]) != 0:
            denom = self.group.pair_prod(us, SK["QVals"])
            key_elt = key_elt / denom 
        shared_key = hashPair(key_elt)
        int_stream = [shared_key[i] ^ CT["C"][i] for i in range(len(shared_key))] 
        return bytes(int_stream)

    def hashOntoG1(self, identifier):
        return self.group.hash(identifier, type=G1)

if __name__ == "__main__":
    scheme = HIDE_GS()

    msk, pp = scheme.setup()
    ID = ["edu", "jhu"]
    ID2 = ["edu", "jhu", "cs", "becgabri"]
    print("Extracting key for ID")
    sk_edu = scheme.keyGen(ID, msk, pp)

    msg1 = b"a" * 64
    print("Encrypting to ID")
    ct1 = scheme.encrypt(msg1, ID, pp)
    print("Attempting decryption")
    pt1 = scheme.decrypt(ct1, sk_edu)
    if pt1 == msg1: 
        print("Decryption was correct!")
    else: 
        print("Decryption failed to give correct result. Result was {}".format(pt1)) 
 
    print("Delegating key to ID2...")
    sk_gab = scheme.delegate(pp, sk_edu, ID2)
    msg2 = b"b" * 64
    print("Encrypting to ID2")
    ct2 = scheme.encrypt(msg2, ID2, pp)  
    print("Attempting decryption")
    pt2 = scheme.decrypt(ct2, sk_gab)
    if pt2 == msg2:
        print("Decryption was correct!")
    else: 
        print("Decryption failed to give correct result. Result was {}".format(pt2))
 
