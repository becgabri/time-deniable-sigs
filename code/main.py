 
from HIBE.parallelize_hibenc_lew11 import HIBE_LW11 
import timelockpuzzle.puzzle as puzzle 
import math
from charm.toolbox.pairinggroup import GT, PairingGroup 
import sys
import threading
from cryptography.hazmat.primitives import hashes
from datetime import datetime
import time
import copy 

TIME_SIZE_L = 32 # this is the length of the path in the tree
N = 2 #controls the identity tree (makes it N-ary)
MAX_TIME = N**TIME_SIZE_L - 1 # this is the maximum time supported
MACHINE_SPEED = 5883206 # this is the poor man's way, just timed how long it took on my machine

# It's expected that id here is a binary string 
def encodeIdentity(id):
    list_id = []
    curr_id = ""
    for _, val in enumerate(id):
        curr_id += val
        list_id.append(curr_id)
    return list_id

# attempts to represent n in the base b 
# returns a list of elements z that satisfies
# \sum i in len(z) b^i * z[i] = m and len(z) = padd_size
def repr_base(m, b, padd_size):
    if b < 1:
        raise ValueError('Base you want to use must be a positive number')
    if m < 0: 
        raise ValueError('Number you want to represent must also be positive')

    repr = []
    accum = m
    i = 1
    while accum != 0:
        curr_val = accum % (b**i)
        val_at_idx = int(curr_val / b**(i-1)) 
        repr.append(val_at_idx)
        accum -= curr_val
        i += 1
    if padd_size > len(repr):
        repr.extend([0]*(padd_size - len(repr)))
    return repr

def reconstruct_num(list_vals, base_b):
    sum = 0
    for idx, val in enumerate(list_vals):
        sum += (val * base_b**idx)
    return sum 

def findPrefix(list_sk_t, t_prime):
    t_prime_bin = bin(t_prime)[2:].zfill(TIME_SIZE_L)

    # start search halfway through list -- this is basically binary search
    beg = 0
    end = len(list_sk_t)
    
    while True:
        curr_idx = int(math.floor((end + beg) / 2))
        prefix_cut = t_prime_bin[:len(list_sk_t[curr_idx][0])]
        if prefix_cut == list_sk_t[curr_idx][0]:
            # end condition
            # print("Returning index: {}\nPrefix: {}\nActual ID: {}\n".format(curr_idx, list_sk_t[curr_idx][0], t_prime_bin))
            return curr_idx
        elif int(prefix_cut,2) > int(list_sk_t[curr_idx][0], 2):
            beg = curr_idx
        else:
            end = curr_idx
    
def serializerHelper(group, pairing_elt, shared_dict, needed_idx):
    #group, pairing_elt, shared_dict, needed_idx = args
    shared_dict[needed_idx] = group.serialize(pairing_elt, compression=False)

def deserializerHelper(group, pairingBytes, shared_dict, needed_idx):
    shared_dict[needed_idx] = group.deserialize(pairingBytes, compression=False)

def pointCompressDecompress(compress_decompress, list_keys):
    list_threads = []
    group = PairingGroup('SS512')
    for _, val in enumerate(list_keys):
        actual_keys = val[1]
        for key, vals in actual_keys.items():
            if key == 'K':
                for _, val2 in enumerate(vals):
                    for i in range(len(val2)):
                        t = threading.Thread(target=compress_decompress, args=(group, val2[i], val2, i,))
                        list_threads.append(t)
            elif key == 'g':
                for _, val2 in enumerate(vals):
                    for i in range(len(val2)):
                        t = threading.Thread(target=compress_decompress, args=(group, val2[i], val2, i,))
                        list_threads.append(t) 
    for thread in list_threads:
        thread.start()
    for thread in list_threads:
        thread.join()


def serialize(list_keys):
    pointCompressDecompress(serializerHelper, list_keys)   

    byte_str = b""
    for _, val in enumerate(list_keys):
        byte_str += val[0].encode() + b"-"
        for key, mtx in val[1].items():
            if key == "K":
                byte_str += b"["
                for _, val2 in enumerate(mtx):                    
                    byte_str += b"["+b"".join([val2[x] + b"," for x in range(len(val2))]) + b"]"
                byte_str += b"]"
            elif key == 'g': 
                byte_str += b"[" 
                for _, val2 in enumerate(mtx):
                    byte_str += b"["+b"".join([val2[x] + b"," for x in range(len(val2))]) + b"]"  
                byte_str += b"]"
        #byte_str += b"]"   
    return byte_str 

# grabs next list of the form [elt1,elt2,elt3,elt4,]
# expects the starting character [ to be present  
# sets idx to be one character index beyond ] 
def grabNextComponent(idx, search_string):
    i = idx
    if search_string[i] != ord("["):
        raise ValueError("Outer component must start with [")
    i = i + 1 # jump over start of outer array
    component = []
    while search_string[i] != ord("]"):
        compr_pairing_elt = b""
        while search_string[i] != ord(","):
            compr_pairing_elt += bytes([search_string[i]])
            i += 1
        component.append(compr_pairing_elt)
        i += 1 # jump over comma 
    return i+1, component



def deserialize(byte_string):
    list_keys = []
    # don't know the end condition yet
    idx = 0
    while idx < len(byte_string):
        byte_id = bytearray()
        while byte_string[idx] != ord("-"):
            byte_id += bytes([byte_string[idx]])
            idx+=1
        dict_for_key = {}
        idx += 1 # jump over -
     
        if byte_string[idx] != ord('['):
            raise ValueError("Encoding is incorrect")
        idx += 1 # jump over start of K indicated by [ 
        dict_for_key['K'] = []
        while True:
            idx, component = grabNextComponent(idx, byte_string)

            dict_for_key['K'].append(component)

            if byte_string[idx] == ord(']'): ## this was a double break
                break
        
        idx += 1 # -- jump over ']' that caused break 
        if byte_string[idx] != ord('['):
            raise ValueError("Incorrect decoding, g should be next")
        idx += 1 # jump over beginning of g
        dict_for_key['g'] = []
        while True:
            idx, component = grabNextComponent(idx, byte_string)
            
            dict_for_key['g'].append(component)
             
            if byte_string[idx] == ord(']'): ## this was a double break
                break
            
        list_keys.append(( byte_id.decode(), dict_for_key))
        idx = idx + 1 # jump over the final ], should be start of another key identifier next
    pointCompressDecompress(deserializerHelper, list_keys)
    return list_keys 
        
         

class TimeDeniableSig:

    def KeyGen(self, timeGap, secParam):
        # this is the easiest one, just the 
        self.group = PairingGroup('SS512')
        self.hibe = HIBE_LW11(self.group)
                
        msk, pp = self.hibe.setup()
        return ((pp,timeGap), (pp,timeGap,msk))

    # t_prime - a number in the appropriate range t_prime <= t 
    def FSDelegate(self, pk, t, sk_t, t_prime):
        if t_prime > t: 
            raise ValueError("Cannot delegate off functional key of lower value t")
        _, list_sk_t = sk_t 
        new_list = []
        #find prefix using binary search 
        idx_for_prefix = findPrefix(list_sk_t, t_prime)
        prefix_len = len(list_sk_t[idx_for_prefix][0]) 
        t_prime_as_bits = bin(t_prime)[2:].zfill(TIME_SIZE_L)
	
        #print("T_prime:{}\nPrefix:{}\nKey Index:{}\n".format(t_prime_as_bits, list_sk_t[idx_for_prefix][0], idx_for_prefix))

        # if there are keys before the prefix point, just randomize and keep those
        for i in range(idx_for_prefix):
            #print("Adding re-randomized key for identity: {}\n".format(list_sk_t[i][0]))
            new_list.append((list_sk_t[i][0], self.hibe.delegate(pk, list_sk_t[i][1], encodeIdentity(list_sk_t[i][0]))))

        # take the prefix and delegate off of what needs to be delegated
        # this time, we go from the direction of "root" down to the leaf because in this context that makes more sense
        curr_id = list_sk_t[idx_for_prefix][0]
        curr_id = curr_id[:len(curr_id)-1]
        extract_key = list_sk_t[idx_for_prefix][1]
        for i in range(prefix_len-1, TIME_SIZE_L-1):
            string_left_mask = (1 << (TIME_SIZE_L-i-1)) -1
            if t_prime_as_bits[i] == '0' and int(t_prime_as_bits[i+1:],2) == string_left_mask:
                #print("Adding key for {}\n".format(curr_id+'0'))
                # problem, probably have to call delegate multiple times here :( 
                idAsEncoded = encodeIdentity(curr_id+'0')
                new_list.append((curr_id + '0', self.hibe.delegate(pk, extract_key, idAsEncoded)))
                return new_list
            elif t_prime_as_bits[i] == '1' and i != (TIME_SIZE_L - 1):
                #print("Adding key for {}\n".format(curr_id+'0'))
                idAsEncoded = encodeIdentity(curr_id+'0')
                new_list.append((curr_id + '0', self.hibe.delegate(pk, extract_key, idAsEncoded)))

            curr_id += t_prime_as_bits[i]

        if t_prime_as_bits[TIME_SIZE_L-1] == '0' and t_prime < t: 
            #print("Adding key for {}\n".format(t_prime_as_bits))
            idAsEncoded = encodeIdentity(t_prime_as_bits)
            new_list.append((t_prime_as_bits, self.hibe.delegate(pk, extract_key, idAsEncoded))) 

        return new_list

    # going down from the root
    # sk_prime - mpk and msk from HIBE
    # t - a number within the appropriate range t < 2^TIME_SIZE_L
    def FSKeygen(self, sk_prime, t):
        pk, sk = sk_prime 
        list_keys = []
        t_as_bits = bin(t)[2:].zfill(TIME_SIZE_L) 
        curr_id = ''

        # ignoring the edge case that messes everything up
        if t == (1 << TIME_SIZE_L) -1:
            raise ValueError("Do not support extracting key of maximum value {}".format((1 << TIME_SIZE_L)-1))
        
        for i in range(TIME_SIZE_L-1):
            string_left_mask = (1 << (TIME_SIZE_L - i -1)) - 1
            if t_as_bits[i] == '0' and int(t_as_bits[i+1:],2) == string_left_mask:
                add_key = self.hibe.keyGen(encodeIdentity(curr_id+'0'), sk, pk)
                list_keys.append((curr_id+'0', add_key))
                return list_keys
            elif t_as_bits[i] == '1' and i != (TIME_SIZE_L - 1):
                add_key = self.hibe.keyGen(encodeIdentity(curr_id+'0'), sk, pk)
                list_keys.append((curr_id+'0', add_key))
            # you should add here the path you're going down next?  
            curr_id += t_as_bits[i]

        if t_as_bits[TIME_SIZE_L-1] == '0':
            add_key = self.hibe.keyGen(encodeIdentity(t_as_bits), sk, pk)
            list_keys.append((t_as_bits, add_key)) 

        return list_keys

    def FSSign(self, sk, t, m):
        pk_prime, list_keys = sk
        idx = findPrefix(list_keys, t)
        lenPrefix = len(list_keys[idx][0])

        # doing what you commonly do in signature schemes, and using a 
        # hash of the message instead of the actual message, also shoving
        # this into ONE ID vs. have it be in multiple 
        hash_accum = hashes.Hash(hashes.SHA256())
        encoded_msg = m.encode()
        encoded_msg = str(len(encoded_msg)).encode() + encoded_msg
        hash_accum.update(encoded_msg)
        hashed_msg = hash_accum.finalize().hex()

        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)
        encedID = encodeIdentity(t_bin)

        # do some identity packing
        encedID.append(encedID[-1]+hashed_msg)

        curr_key = list_keys[idx][1]
        return self.hibe.delegate(pk_prime, curr_key, encedID)

    # assumption right now is message is a binary string 
    def Sign(self, sk, m, t):
        # produce the signature on the message using the FS
        pk_prime, timeGap, sk_prime = sk
        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)

        list_keys = self.FSKeygen((pk_prime, sk_prime), t)
        s = self.FSSign((pk_prime, list_keys), t, m)

        # note here, doing this clobbers the OG thing
        # after this it's not the same  
        pt = serialize(list_keys)

        _, _, n, a, bar_t, enc_key, enc_msg, _ = puzzle.encrypt(pt, timeGap, MACHINE_SPEED)
        return ((n,a,bar_t,enc_key, enc_msg), s)

    def AltSign(self, vk, m_0, t_0, sigma_0, m, t):
        if t > t_0: 
            raise ValueError("Cannot sign a message on a later timestamp with a key for an earlier one!")
        pk, timeGap = vk

        c, _ = sigma_0 
        n, a, bar_t, enc_key, enc_msg = c 
        keys_as_bytes = puzzle.decrypt(n, a, bar_t, enc_key, enc_msg)
        list_keys = deserialize(keys_as_bytes)
        # need to shrink w/ FS DELEG
        new_list_keys = self.FSDelegate(pk, t_0, (pk, list_keys), t)
        s = self.FSSign((pk, new_list_keys), t, m)
        
        pt = serialize(new_list_keys)
        _, _, n, a, bar_t, enc_key, enc_msg, _ = puzzle.encrypt(pt, timeGap, MACHINE_SPEED)
        return ((n,a,bar_t,enc_key,enc_msg), s)

    #it's assumed m is a string, t is a numerical value
    def Verify(self, vk, sigma, m, t):
        pk,_ = vk
        _, sk_id = sigma
        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)

        # reconstruct the right identity
        hash_accum = hashes.Hash(hashes.SHA256())
        encoded_msg = m.encode()
        encoded_msg = str(len(encoded_msg)).encode() + encoded_msg
        hash_accum.update(encoded_msg)
        hashed_msg = hash_accum.finalize().hex()

        identity = encodeIdentity(t_bin)
        identity.append(identity[-1]+hashed_msg)
                

        # encrypt/decrypt check
        test_elt = self.group.random(GT)
        ct = self.hibe.encrypt(test_elt, identity, pk)

        if self.hibe.decrypt(ct, sk_id) == test_elt:
            return True
        return False

def keyEqual(dict1, dict2):
    for key, outer_list in dict1.items():
        if not key in dict2 or len(dict1[key]) != len(dict2[key]):
            print("Is key {} in dict2? {}. Length in dict1: {}. Length in dict2: {}".format(key in dict2, len(dict1[key]), len(dict2[key])))
            return False
        # {'K': [[Key 1 has 10 components      ], ... [Key i has 10 components       ]
        for idx, vals in enumerate(outer_list):
            # one more nested list here 
            if len(vals) != len(dict2[key][idx]):
                print("Length of dict1[{}][{}] is {} while dict2 length is {}".format(key, idx, len(vals), len(dict2[key][idx])))
                return False
            # one more layer 
            for id2, val2 in enumerate(vals):
                if val2 != dict2[key][idx][id2]:
                    print("dict1[{}][{}][{}] value is {} while dict2 value is {}".format(key, idx, id2,val2, dict2[key][idx][id2]))
                    return False
    return True

def listKeysEqual(list1, list2):
    if len(list1) != len(list2):
        return False
    for id, key_tuple in enumerate(list1):
        key_id, key_val = key_tuple
        if key_id != list2[id][0]:
            print("Key ids are different {} != {}".format(key_id, list2[id][0]))
            return False
        if not keyEqual(key_val, list2[id][1]):
            return False
    return True

def deepEqual(list1, list2): 
    if len(list1) != len(list2):
        return False
    for i,val in enumerate(list1):
        if val != list2[i]:
            return False
    return True

if __name__ == "__main__":
    """
    simpleTest1 = repr_base(5, 2)
    if reconstruct_num(simpleTest1,2) != 5:
        print("Failed simplest test")
    
    simpleTest2 = repr_base(7,3)
    if reconstruct_num(simpleTest2,3) != 7:
        print("Failed simplest test")
    
    print("Staring Time Deniable Sig stuff")
    """
    ts = TimeDeniableSig()
    
    fakeTimeParam = 60*60*24
    # I don't know what the security of the pairing scheme actually corresponds to :( 
    # according to charm, order of base field for EC used in HIBE is 512, SS = Super Singular curve -- don't know but it could be that this corresponds to 80 bits of security (1024 bit DH)
    vk, sk = ts.KeyGen(fakeTimeParam, 256)
    
    m1 = "Cryptography rearranges power: it configures who can do what, from what."
    t1 = 1634098632 # just took this
    curr_date = datetime.fromtimestamp(t1)
    print("Date and time used with: {}".format(curr_date))
    avg_time = 0
    for i in range(50):
        beg_ticker = time.time()
        ts.Sign(sk, m1,t1)
        duration = time.time() - beg_ticker
        print(duration)
        avg_time += duration
    avg_time = avg_time / 50
    print("Average time for parameter {} was {} seconds".format(fakeTimeParam/60,avg_time))
    sys.exit()
    """ 
    # need to check right if deserialization/serialization is correct
    pk, timeGap, sk_prime = sk
    list_keys = ts.FSKeygen((pk, sk_prime), 13)
    encoded = serialize(list_keys)
    # remember, this function wrecks the current representation :P
    pointCompressDecompress(deserializerHelper, list_keys)
    decoded_keys = deserialize(encoded)
    if not listKeysEqual(list_keys, decoded_keys):
        print("Problem with encoder/decoder")
        sys.exit()
    else:
        print("Key encoding seems okay, checking other stuff...")
    """ 

    m1 = "Some text"
    t1 = int(time.time())
    sig1 = ts.Sign(sk, m1, t1)
 
    if not ts.Verify(vk, sig1, m1, t1):
        print("Verification failed")
    else:
        print("Passed Sign test")
    sys.exit()
    m2 = bin(15)[2:].zfill(4)
    t2 = 10
    sig2 = ts.AltSign(vk, m1, t1, sig1, m2, t2)

    if not ts.Verify(vk, sig2, m2, t2):
        print("Verification failed")
    else:
        print("Passed first AltSign test")

    m3 = bin(7)[2:].zfill(4)
    t3 = 2
    sig3 = ts.AltSign(vk, m2, t2, sig2, m3, t3)

    if not ts.Verify(vk, sig3, m3, t3):
        print("Verification failed")
    else: 
        print("Passed second AltSign test")
    

    """ 
    dummy_sk = (0,0)
    print("Testing FSKeygen...")
    
    fsKeygen = [['0'], ['0', '100'], ['0', '10']]
    for i, val in enumerate([3, 4, 5]):
        assert( deepEqual(FSKeygen(dummy_sk, val), fsKeygen[i])), "Incorrect key extracted for FSKeygen with time size 3, value {}".format(val)
    
    TIME_SIZE_L = 4 
    fsKeygen = [['00', '0100']]
    for i, val in enumerate([4]):
        assert( deepEqual(FSKeygen(dummy_sk, val), fsKeygen[i])), "Incorrect key extracted for FSKeygen with time size 4, value {}".format(val)

    print("Passed FSKeygen tests.")
    
    TIME_SIZE_L = 3
    print("Testing findPrefix...")

    six_key = ['0', '10', '110']
    assert ( findPrefix(six_key,4) == 1), "Incorrect prefix for 4 = 100, should be 1"

    assert ( findPrefix(six_key, 3) == 0), "Incorrect prefix for 3 = 011, should be 2"
    assert ( findPrefix(six_key, 2) == 0), "Incorrect prefix for 2 = 010, should be 2"

    TIME_SIZE_L = 4
    fourteen_key = ['0', '10', '110', '1110']
    assert ( findPrefix(fourteen_key, 12) == 2), "Incorrect prefix for 12 = 1100, should be 1"
    assert ( findPrefix(fourteen_key, 3) == 0), "Incorrect prefix for 3 = 0011, should be 3"
    assert ( findPrefix(fourteen_key, 5) == 0), "Incorrect prefix for 5 = 0101, should be 3"
    print("Passed findPrefix tests.")

    TIME_SIZE_L = 3

    print("Testing FSDelegate...")
    four_key = ['0', '100']
    dummy_pk = 0
    assert( deepEqual(FSDelegate(dummy_pk, 6, (dummy_pk, six_key), 4), four_key)), "Incorrect delegate for time param 3, going from 6 to 4"
    assert( deepEqual(FSDelegate(dummy_pk, 6, (dummy_pk, six_key), 3), ['0'])), "Incorrect delegate for time param 3, going from 6 to 3"
    
    TIME_SIZE_L = 4
    four_key_tl4 = ['00', '0100']
    seven_key_tl4 = ['0']
    ten_key_tl4 = ['0', '100', '1010']
    assert(  deepEqual(FSDelegate(dummy_pk, 14, (dummy_pk, fourteen_key), 4), four_key_tl4)), "Incorrect delegate for time param 4 going from 14 to 4"
    assert(  deepEqual(FSDelegate(dummy_pk, 14, (dummy_pk, fourteen_key), 7), seven_key_tl4)), "Incorrect delegate for time param 4 going from 14 to 7"
    assert(  deepEqual(FSDelegate(dummy_pk, 14, (dummy_pk, fourteen_key), 10), ten_key_tl4)), "Incorrect delegate for time param 4 going from 14 to 10"
    print("Passed FSDelegate tests.")
    """
