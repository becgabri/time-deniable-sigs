import random 
#from HIDE.hidenc import HIDE_GS 
#from HIBE.hibenc_lew11 import HIBE_LW11
from CLLWW12.hibenc_cllww12 import HIBE_CLLWW12  
from timelockpuzzle.puzzle import TLP 
import math
from charm.toolbox.pairinggroup import PairingGroup 
import sys
import queue
from multiprocessing import Process, Queue
import threading
from cryptography.hazmat.primitives import hashes
from datetime import datetime
import time
import copy 
import csv
import pickle

# Testing related functionality
# -- this should really be in another file 
import unittest
import logging

TIME_SIZE_L = 2#5#8 # this is the length of the path in the tree
N = 256#10#17 # controls the identity tree (makes it N-ary)
MAX_TIME = N**TIME_SIZE_L - 1 # this is the maximum time supported
MACHINE_SPEED = 5883206
SECPERMIN = 60
FAKETIMEPARAM = 7*24*60*SECPERMIN
#FAKETIMEPARAM = 2

FILENAME = "tds_vary_n_ary.csv"

# Require: id is a string
# Effects: outputs a list of strings as long as ID -- this
# is needed for encoding according to the original work
# of lewko-waters 
def encodeIdentity(id):
    list_id = []
    curr_id = bytearray()
    for _, val in enumerate(id):
        curr_id += bytearray([val])
        list_id.append(curr_id[:])
    return list_id

# attempts to represent n in the base b 
# returns a string z that satisfies
# \sum i in len(z) b^(len(z)-1-i) * z[i] = m and len(z) = padd_size
def repr_base(m, b, padd_size):
    if b < 1:
        raise ValueError('Base you want to use must be a positive number')
    if m < 0: 
        raise ValueError('Number you want to represent must also be positive')

    repr_ = bytearray()
    accum = m
    i = 1
    while accum != 0:
        curr_val = accum % (b**i)
        val_at_idx = int(curr_val / b**(i-1)) 
        repr_ += bytearray([val_at_idx])
        accum -= curr_val
        i += 1
    if padd_size > len(repr_):
        repr_ += bytearray([0]*(padd_size - len(repr_)))
    repr_.reverse()
    return repr_

# Requires: numerical_repr is a string where each character
# is one of 0... b-1. Where the highest index is assoc. with b^0 (this is the opposite of normal where lowest index is assoc. with b^0)
def reconstruct_num(numerical_repr, base_b):
    length_str = len(numerical_repr)
    sum_ = 0
    for i in range(length_str):
        sum_ += numerical_repr[i] * base_b**(length_str-1-i)
    return sum_ 

def findPrefix(list_sk_t, t_prime):
    t_prime_str = repr_base(t_prime, N, TIME_SIZE_L)

    # start search halfway through list -- this is basically binary search
    beg = 0
    end = len(list_sk_t)
    
    while True:
        curr_idx = int(math.floor((end + beg) / 2))
        prefix_cut = t_prime_str[:len(list_sk_t[curr_idx][0])]
        if prefix_cut == list_sk_t[curr_idx][0]:
            # end condition
            # print("Returning index: {}\nPrefix: {}\nActual ID: {}\n".format(curr_idx, list_sk_t[curr_idx][0], t_prime_bin))
            return curr_idx
        elif reconstruct_num(prefix_cut,N) > reconstruct_num(list_sk_t[curr_idx][0], N):
            beg = curr_idx
        else:
            end = curr_idx
    
def serializerHelper(group, pairing_elt, shared_dict, needed_idx):
    shared_dict[needed_idx] = group.serialize(pairing_elt, compression=False)

def deserializerHelper(group, pairingBytes, shared_dict, needed_idx):
    shared_dict[needed_idx] = group.deserialize(pairingBytes, compression=False)

def pointCompressDecompress(compress_decompress, list_keys):
    list_threads = []
    group = PairingGroup("BN254")
    for _,val in enumerate(list_keys):
        actual_keys = val[1]
        for key, vals in actual_keys.items():
            if key == 'K':
                for _,val2 in enumerate(vals):
                    for i in range(len(val2)):
                        t = threading.Thread(target=compress_decompress, args=(group, val2[i], val2, i,))
                        list_threads.append(t)
            elif key == 'g':
                for _,val2 in enumerate(vals):
                    for i in range(len(val2)):
                        t = threading.Thread(target=compress_decompress, args=(group, val2[i], val2, i,))
                        list_threads.append(t)
    for thread in list_threads:
        thread.start()
    for thead in list_threads:
        thread.join()

def serialize(list_keys):
    group = PairingGroup("BN254")
    serialize_keys = []
    for idx,val in enumerate(list_keys):
        new_serialized_key = {"K_0":[], "K_I":[]}
        actual_keys = val[1]
        for idx, val2 in enumerate(actual_keys["K_0"]):
            new_serialized_key["K_0"].append(group.serialize(val2 ,compression=False))
        for _, val3 in enumerate(actual_keys["K_I"]):
            new_serialized_key["K_I"].append([])
            for i in range(len(val3)):
                new_serialized_key["K_I"][-1].append(group.serialize(val3[i], compression=False))
        serialize_keys.append((val[0], new_serialized_key))
    res = pickle.dumps(serialize_keys)
    return res

def deserialize(str_stuff):
    group = PairingGroup("BN254")
    list_keys = pickle.loads(str_stuff)
    for idx,val in enumerate(list_keys):
        actual_keys = val[1]
        for idx, val2 in enumerate(actual_keys["K_0"]):
            actual_keys["K_0"][idx] = group.deserialize(val2 ,compression=False)
        for _, val3 in enumerate(actual_keys["K_I"]):
            for i in range(len(val3)):
                val3[i] = group.deserialize(val3[i], compression=False)
    return list_keys

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
"""
def deserialize(byte_string):
    list_keys = []
    idx = 0
    while idx < len(byte_string):
        byte_id = bytearray()
        while byte_string[idx] != ord('-'):
            byte_id += bytes([byte_string[idx]])
            idx += 1
        dict_for_key = {}
        idx += 1 # jump over - 
        key_for_dict = chr(byte_string[idx])
        if key_for_dict != 'K' and key_for_dict != 'g':
            raise ValueError("Encoding is incorrect")
        idx += 1
        if byte_string[idx] != ord('['):
            raise ValueError("Encoding is incorrect")
        idx += 1 # jump over start of K indicated by [ 
        dict_for_key[key_for_dict] = []
        while True: 
            idx, component = grabNextComponent(idx, byte_string)
            dict_for_key[key_for_dict].append(component)
            if byte_string[idx] == ord(']'):
                break

        idx += 1
        next_key = chr(byte_string[idx])
        if (next_key != 'K' and next_key != 'g') or next_key == key_for_dict:
            raiseValueError("Encoding is incorrect")
        idx += 1
        if byte_string[idx] != ord('['):
            raiseValueError("Encoding is incorrect")
        idx += 1
        dict_for_key[next_key] = []
        while True: 
            idx, component = grabNextComponent(idx, byte_string)
            dict_for_key[next_key].append(component)
            if byte_string[idx] == ord(']'):
                break
        list_keys.append((byte_id, dict_for_key))
        idx += 1
    pointCompressDecompress(deserializerHelper, list_keys)
    return list_keys
"""

"""
def pointCompressDecompress(compress_decompress, list_keys):
    list_procs = []
    group = PairingGroup('BN254')
    for _, val in enumerate(list_keys):
        actual_keys = val[1]
        for key, vals in actual_keys.items():
            if key == 'QVals':
                for i in range(len(vals)):
                    compress_decompress(group, vals[i], vals, i)
            elif key == 'S':
                compress_decompress(group, vals, actual_keys, 'S')

def serialize(list_keys):
    print("In beginning of serialize with list {}".format(list_keys))
    pointCompressDecompress(serializerHelper, list_keys)   
    print("Now have list: {}".format(list_keys))
    byte_str = b""
    for _, val in enumerate(list_keys):
        byte_str += val[0] + b"-"
        
        for key, mtx in val[1].items():
            byte_str += key.encode()
            byte_str += b"["
            if key == "S":
                byte_str += mtx
            else: 
                byte_str += b",".join(mtx)
            byte_str += b"]"
    return byte_str 

def deserialize(byte_string):
    log = logging.getLogger("deserializer")
    log.debug("Debugging deserialize, format of input is: {}".format(byte_string))
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
        for j in range(2):
            comp = byte_string[idx:]
            end_key = comp.find(b"[")
            key_for_dict = comp[:end_key] 
            if key_for_dict != b'S' and key_for_dict != b'QVals': 
                raise ValueError("Encoding is incorrect")
            idx += len(key_for_dict) 
            if byte_string[idx] != ord('['):
                raise ValueError("Encoding is incorrect")
            idx += 1 # jump over start of key elt indicated by [ 
        
            next_comp = byte_string[idx:]
            end_comp = next_comp.find(b"]")
            next_val = next_comp[:end_comp]
            if key_for_dict == b"QVals":
                #edge case
                if len(next_val) == 0:
                    next_val = []
                else:
                    next_val = next_val.split(b",")
            dict_for_key[key_for_dict.decode()] = next_val
            idx += end_comp + 1
        
        # add key
        list_keys.append((byte_id, dict_for_key))

    pointCompressDecompress(deserializerHelper, list_keys)
    log.debug("Got list of keys, returning...")
    return list_keys 
"""       
# the things we do because python and multithreading and pickling and GILs UGH :P 
def parallel_extr(q, sk, pp, id_v):
    group = PairingGroup('BN254')
    tmp_kg = HIBE_CLLWW12(group)
    res = tmp_kg.keyGen(encodeIdentity(id_v), sk, pp)
    """
    a_key = None
    try:
        a_key = serialize([(str(id_v), res)])
    except:
        print("Starting parallel_extr with: sk = {}, pp = {}, id_v = {}".format(sk, pp, id_v))
        print("experienced error in serialize")
        print("res key was: {}".format(res))
    """
    q.put((str(id_v), res))

class TimeDeniableSig:
    # timeGap = number of seconds the time lock should last
    def KeyGen(self, timeGap, secParam):
        # this is the easiest one, just the
        group = PairingGroup('BN254')
        self.hibe = HIBE_CLLWW12(group)
        #self.hibe = HIBE_LW11(group)
        self.tlp = TLP(timeGap, MACHINE_SPEED)
        # adding one for the message 
        msk, pp = self.hibe.setup(TIME_SIZE_L+1)
        #msk, pp = self.hibe.setup()
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
        t_prime_as_base_n = repr_base(t_prime, N, TIME_SIZE_L)
	
        #print("T_prime:{}\nPrefix:{}\nKey Index:{}\n".format(t_prime_as_base_n, list_sk_t[idx_for_prefix][0], idx_for_prefix))
        # if there are keys before the prefix point, just randomize and keep those
        for i in range(idx_for_prefix):
            #print("Adding re-randomized key for identity: {}\n".format(list_sk_t[i][0]))
            new_list.append((list_sk_t[i][0], self.hibe.delegate(pk, list_sk_t[i][1], encodeIdentity(list_sk_t[i][0]))))

        # take the prefix and delegate off of what needs to be delegated
        # this time, we go from the direction of "root" down to the leaf because in this context that makes more sense
        curr_id = list_sk_t[idx_for_prefix][0][:]
        extract_key = list_sk_t[idx_for_prefix][1]
        for i in range(prefix_len, TIME_SIZE_L):
            string_left_mask = (N**(TIME_SIZE_L-i)) -1
            # if t_prime_as_base_n[i] != str(N-1)
            if reconstruct_num(t_prime_as_base_n[i:],N) == string_left_mask:
                break
            elif t_prime_as_base_n[i] != 0:
                for node in range(int(t_prime_as_base_n[i])):
                    id_key = curr_id + bytearray([node])
                    #print("Adding key for {}".format(curr_id+str(node)))
                    idAsEncoded = encodeIdentity(id_key)
                    new_list.append((id_key, self.hibe.delegate(pk, extract_key, idAsEncoded)))

            curr_id += bytearray([t_prime_as_base_n[i]])
        #edge case
        if len(curr_id) == 0:
            #print("Adding re-randomized key for identity: {}\n".format(list_sk_t[idx_for_prefix][0]))
            new_list.append((list_sk_t[idx_for_prefix][0], self.hibe.delegate(pk, list_sk_t[idx_for_prefix][1], encodeIdentity(list_sk_t[idx_for_prefix][0]))))
        else:
            if curr_id[-1] != N-1: 
                #print("Adding key for {}\n".format(curr_id))
                idAsEncoded = encodeIdentity(curr_id)
                new_list.append((curr_id, self.hibe.delegate(pk, extract_key, idAsEncoded))) 
        return new_list

    # going down from the root
    # sk_prime - mpk and msk from HIBE
    # t - a number within the appropriate range t < N^TIME_SIZE_L - 1 # don't want max b/c the tree's messed up
    def FSKeygen(self, sk_prime, t):
        pk, sk = sk_prime 
        list_keys = []
        t_in_base_n = repr_base(t, N, TIME_SIZE_L) 
        curr_id = bytearray()
        key_id_list = []
        for i in range(TIME_SIZE_L):
            string_left_mask = (N**(TIME_SIZE_L-i)) - 1
            if reconstruct_num(t_in_base_n[i:],N) == string_left_mask:
                break
            elif t_in_base_n[i] != 0:
                for node in range(int(t_in_base_n[i])):
                    #print("Adding key for {}".format(curr_id+str(node)))
                    id_key = curr_id+bytearray([node])
                    key_id_list.append(id_key)
                    add_key = self.hibe.keyGen(encodeIdentity(id_key), sk, pk)
                    list_keys.append((id_key, add_key))

            # you should add here the path you're going down next 
            curr_id += bytearray([t_in_base_n[i]])

        # edge case 
        if curr_id == "":
            for node in range(int(t_in_base_n[i])+1):
                #print("Adding key for {}".format(curr_id+str(node)))
                id_key = curr_id + bytearray(node)
                key_id_list.append(id_key)
                add_key = self.hibe.keyGen(encodeIdentity(id_key), sk, pk)
                list_keys.append((id_key, add_key))
        else:
            if curr_id[-1] != str(N-1):
                #print("Adding key for {}".format(curr_id))
                key_id_list.append(curr_id)
                add_key = self.hibe.keyGen(encodeIdentity(curr_id), sk, pk)
                list_keys.append((curr_id, add_key)) 
        """ 
        #fill out all the keys using a thread pool 
        q = Queue()
        thread_l = []
        log = logging.getLogger("deserializer")
        for key_id in key_id_list:
            log.debug("Creating process for key {}".format(key_id)) 
            thread_l.append(Process(target=parallel_extr, args=(q, sk, pk, key_id,))) 
            #parallel_extr(q, sk, pk, key_id)
        log.debug("The length of key_id_list is {} there are {} proc tasks".format(len(key_id_list),len(thread_l)))
        for thread in thread_l: 
            thread.start()
        for thread in thread_l:
            log.debug("Joining...")
            thread.join()
        log.debug("Got through all proc joins")

        #list_keys = [None] * len(key_id_list)       
        list_keys = []
        for i in range(len(key_id_list)):
            log.debug("grabbing key") 
            byte_key = q.get()
            #a_key = deserialize(byte_key)
            log.debug("got key")
            #id_place = key_id_list.index(a_key[0][0])
            #list_keys[id_place] = a_key[0]
            list_keys.append(byte_key)
        log.debug("Grabbed all keys")
        """
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

        t_as_str = repr_base(t, N, TIME_SIZE_L)
        encedID = encodeIdentity(t_as_str)

        # do some identity packing
        encedID.append(encedID[-1]+bytearray(hashed_msg,"utf-8"))

        curr_key = list_keys[idx][1]
        return self.hibe.delegate(pk_prime, curr_key, encedID)

    # assumption right now is message is a binary string 
    def Sign(self, sk, m, t):
        # produce the signature on the message using the FS
        pk_prime, timeGap, sk_prime = sk

        list_keys = self.FSKeygen((pk_prime, sk_prime), t)
        print(len(list_keys)) 
        s = self.FSSign((pk_prime, list_keys), t, m)

        # note here, doing this clobbers the OG thing
        # after this it's not the same  
        pt = serialize(list_keys)
        #puzzle_ticker = time.time() 
        t, n, a, enc_msg, enc_key = self.tlp.encrypt(pt)
        #end_time = time.time() - puzzle_ticker
        #print("Time encrypting the signing key: {}".format(end_time))
        return ((n,a,t,enc_msg, enc_key), s)

    def AltSign(self, vk, m_0, t_0, sigma_0, m, t):
        if t > t_0: 
            raise ValueError("Cannot sign a message on a later timestamp with a key for an earlier one!")
        pk, timeGap = vk

        c, _ = sigma_0 
        n, a, bar_t, enc_msg, enc_key = c
        keys_as_bytes = self.tlp.decrypt(bar_t, n, a, enc_msg, enc_key)
        list_keys = deserialize(keys_as_bytes)
        # need to shrink w/ FS DELEG
        new_list_keys = self.FSDelegate(pk, t_0, (pk, list_keys), t)
        s = self.FSSign((pk, new_list_keys), t, m)
        
        pt = serialize(new_list_keys)
        t, n, a, enc_msg, enc_key = self.tlp.encrypt(pt)
        return ((n,a,t,enc_msg,enc_key), s)

    #it's assumed m is a string, t is a numerical value
    def Verify(self, vk, sigma, m, t):
        pk,_ = vk
        _, sk_id = sigma
        t_as_str = repr_base(t, N, TIME_SIZE_L)

        # reconstruct the right identity
        hash_accum = hashes.Hash(hashes.SHA256())
        encoded_msg = m.encode()
        encoded_msg = str(len(encoded_msg)).encode() + encoded_msg
        hash_accum.update(encoded_msg)
        hashed_msg = hash_accum.finalize().hex()

        identity = encodeIdentity(t_as_str)
        identity.append(identity[-1]+bytearray(hashed_msg, "utf-8"))
                

        # encrypt/decrypt check
        test_msg = self.hibe.getRandomPT()
        ct = self.hibe.encrypt(test_msg, identity, pk)

        if self.hibe.decrypt(ct, sk_id) == test_msg:
            return True
        return False

def keyEqual(dict1, dict2):
    for key, outer_list in dict1.items():
        if not key in dict2:
            print("Missing key {} in dict1 from dict2".format(key))
        if isinstance(outer_list, list): 
            if len(dict1[key]) != len(dict2[key]):
                print("Length of key {} in dict1: {}. Length in dict2: {}".format(key, len(dict1[key]), len(dict2[key])))
                return False
            for idx, val in enumerate(outer_list):
                if val != dict2[key][idx]:
                    print("dict1[{}][{}] value is {} while dict2 value is {}".format(key, idx, val, dict2[key][idx]))
                    return False
        else:
            if outer_list != dict2[key]:
                print("Key:{}. Value in dict1:{}. Value in dict2:{}".format(key, outer_list, dict2[key]))
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

# not a true deep equal, only works for the identity assoc.
# with the key, not the key itself b/c the alg. is randomized
# list1 = [(id1, key1), ... ,(idn, keyn)]
# list2 = [id1, ... , idn]
def deepEqual(list1, list2): 
    if len(list1) != len(list2):
        return False
    for i,val in enumerate(list1):
        if val[0] != list2[i]:
            return False
    return True


# unit testing info 
class TestUtils(unittest.TestCase):
    def test_repr_1(self):
        five = repr_base(5, 2,3)
        self.assertEqual(reconstruct_num(five, 2),5)

    def test_repr_2(self):
        seven = repr_base(7,3,3)
        self.assertEqual(reconstruct_num(seven, 3),7)

class TestTreeThreeSig(unittest.TestCase):
    def setUp(self):
        global TIME_SIZE_L, N
        N = 3
        TIME_SIZE_L = 2 # this is the default, if you need something different you have to just re-run everything :( 
        self.ts = TimeDeniableSig()
        # param only needed for correctness so setting it
        # to be very low
        vk, sk = self.ts.KeyGen(1, 256)
        self.vk = vk
        self.sk = sk

    def test_simpleKeyGens(self):
        pk, timeGap, sk_prime = self.sk
        seven_key = self.ts.FSKeygen((pk, sk_prime), 7)
        seventh_k = [bytearray([0]), bytearray([1]), bytearray([2, 0]), bytearray([2, 1])]
        self.assertEqual(deepEqual(seven_key, seventh_k),True)

        self.assertEqual(deepEqual(self.ts.FSKeygen((pk, sk_prime), 0),[bytearray([0, 0])]), True)

        self.assertEqual(deepEqual(self.ts.FSKeygen((pk, sk_prime), 3), [bytearray([0]),bytearray([1, 0])]), True)

    def test_simpleDelegate(self):
        pk, timeGap, sk_prime = self.sk 
        fifth_key = self.ts.FSKeygen((pk, sk_prime), 5)
        fifth_ids = [bytearray([0]), bytearray([1])]
        self.assertEqual(deepEqual(fifth_key, fifth_ids), True)

        two_key = self.ts.FSDelegate(pk, 5, (pk, fifth_key), 2)
        fourth_key = self.ts.FSDelegate(pk, 5, (pk, fifth_key), 4)

        self.assertEqual(deepEqual(two_key, [bytearray([0])]),True)
        self.assertEqual(deepEqual(fourth_key, [bytearray([0]),bytearray([1, 0]),bytearray([1, 1])]),True)
    
    def test_sign_altsign(self):
        m = '12121'
        t = 6
        sigma = self.ts.Sign(self.sk, m, t)
        self.assertEqual(self.ts.Verify(self.vk, sigma, m, t), True)
        
        new_m = '2101201'
        new_t = 1
        new_sigma = self.ts.AltSign(self.vk, m, t, sigma,new_m, new_t) 
        self.assertEqual(self.ts.Verify(self.vk, new_sigma, new_m, new_t), True)
    
class TestDeniableSigs(unittest.TestCase):

    def setUp(self):
        global TIME_SIZE_L, N
        TIME_SIZE_L = 3 # this is the default, if you need something different you have to just re-run everything :( 
        N = 2
        self.ts = TimeDeniableSig()
        # param only needed for correctness so setting it
        # to be very low
        vk, sk = self.ts.KeyGen(1, 256)
        self.vk = vk
        self.sk = sk
    
    def test_serialize(self):
        pk, timeGap, sk_prime = self.sk
        list_keys = self.ts.FSKeygen((pk, sk_prime), 5)
        encoded = serialize(list_keys)
        # remember, this function wrecks the current representation :P
        #pointCompressDecompress(deserializerHelper, list_keys)
        decoded_keys = deserialize(encoded)
        self.assertEqual(listKeysEqual(list_keys, decoded_keys),True)
    
    def test_fskeygen_1(self):
        pk, timeGap, sk_prime = self.sk
        fsKeygen = [[bytearray([0])], [bytearray([0]), bytearray([1, 0, 0])], [bytearray([0]), bytearray([1,0])]]
        for i, val in enumerate([3, 4, 5]):
            self.assertEqual( deepEqual(self.ts.FSKeygen((pk, sk_prime), val), fsKeygen[i]), True) 

    def test_fsdelegate_1(self):    
        pk, timeGap, sk_prime = self.sk
        six_key = self.ts.FSKeygen((pk, sk_prime), 6)
        four_key = [bytearray([0]), bytearray([1,0,0])]
        new_four_key = self.ts.FSDelegate(pk,6,(pk,six_key),4)
        self.assertEqual(deepEqual(new_four_key, four_key), True)
        new_third_key = self.ts.FSDelegate(pk, 6, (pk, six_key), 3) 
        self.assertEqual(deepEqual(new_third_key, [bytearray([0])]), True)
    
    def test_all_sigs(self):
        m1 = "Some text"
        t1 = 5
        sig1 = self.ts.Sign(self.sk, m1, t1)
 
        self.assertEqual(self.ts.Verify(self.vk, sig1, m1, t1), True)
        
        m2 = bin(15)[2:].zfill(4)
        t2 = 2
        sig2 = self.ts.AltSign(self.vk, m1, t1, sig1, m2, t2)

        self.assertEqual(self.ts.Verify(self.vk, sig2, m2, t2), True)

        m3 = bin(7)[2:].zfill(4)
        t3 = 1
        sig3 = self.ts.AltSign(self.vk, m2, t2, sig2, m3, t3)

        self.assertEqual(self.ts.Verify(self.vk, sig3, m3, t3), True)
    

    def test_fskeygen_prefix1(self):
        pk, timeGap, sk_prime = self.sk
        six_key = self.ts.FSKeygen((pk, sk_prime), 6)
        self.assertEqual(findPrefix(six_key,4),1)
        self.assertEqual(findPrefix(six_key, 3),0)
        self.assertEqual(findPrefix(six_key, 2),0)
   
class TestDenSigLargerTree(unittest.TestCase):

    def setUp(self):
        global TIME_SIZE_L, N
        TIME_SIZE_L = 4 
        N = 2
        self.ts = TimeDeniableSig()
        # param only needed for correctness so setting it
        # to be very low
        vk, sk = self.ts.KeyGen(1, 256)
        self.vk = vk
        self.sk = sk

    def test_fsdelegate_2(self):
        pk, timeGap, sk_prime = self.sk
        fourteen_key = self.ts.FSKeygen((pk, sk_prime), 14)
        four_key_tl4 = [bytearray([0, 0]), bytearray([0, 1, 0, 0])]
        seven_key_tl4 = [bytearray([0])]
        ten_key_tl4 = [bytearray([0]), bytearray([1,0,0]), bytearray([1,0,1,0])]

        assert(  deepEqual(self.ts.FSDelegate(pk, 14, (pk, fourteen_key), 4), four_key_tl4)), "Incorrect delegate for time param 4 going from 14 to 4"
        assert(  deepEqual(self.ts.FSDelegate(pk, 14, (pk, fourteen_key), 7), seven_key_tl4)), "Incorrect delegate for time param 4 going from 14 to 7"
        assert(  deepEqual(self.ts.FSDelegate(pk, 14, (pk, fourteen_key), 10), ten_key_tl4)), "Incorrect delegate for time param 4 going from 14 to 10"

    def test_fskeygen_prefix2(self):        
        fourteen_key = [[bytearray([0]), 0], [bytearray([1,0]), 0], [bytearray([1,1,0]), 0], [bytearray([1,1,1,0]),0]]
        assert(findPrefix(fourteen_key, 12) == 2), "Incorrect prefix for 12 = 1100, should be 1"
        assert(findPrefix(fourteen_key, 3) == 0), "Incorrect prefix for 3 = 0011, should be 3"
        assert(findPrefix(fourteen_key, 5) == 0), "Incorrect prefix for 5 = 0101, should be 3"

    def test_fskeygen_2(self):
        pk, timeGap, sk_prime = self.sk
        fsKeygen = [[bytearray([0,0]), bytearray([0,1,0,0])]]
        for i, val in enumerate([4]):
            self.assertEqual(deepEqual(self.ts.FSKeygen((pk,sk_prime), val), fsKeygen[i]), True), "Incorrect key extracted for FSKeygen with time size 4, value {}".format(val)

def calculateSigSize(sig, group_repr):
    sum_b = 0
    for i in range(len(sig[0])):
        if isinstance(sig[0][i], bytes) or isinstance(sig[0][i], str):
            sum_b += len(sig[0][i])
        else:
            sum_b += (sig[0][i].bit_length() + 7) // 8
    sum_a = 0
    for idx, list_elts in enumerate(sig[1]["K"]):
        for gr_elt in list_elts:
            try: 
                sum_a += len(group_repr.serialize(gr_elt))
            except:
                print(gr_elt)
                import pdb; pdb.set_trace()
    for list_elts in sig[1]["g"]:
        for byte_elt in list_elts:
            sum_a += len(byte_elt)
    return (sum_a, sum_b)

# for 
def calculateSigSize2(sig, group_repr):
    sum_b = 0
    for i in range(len(sig[0])):
        if isinstance(sig[0][i], bytes) or isinstance(sig[0][i], str):
            sum_b += len(sig[0][i])
        else:
            sum_b += (sig[0][i].bit_length() + 7) // 8
    sum_a += len(group_repr.serialize(sig[1]['S']))
    for i in range(len(sig[1]['QVals'])):
        sum_a += len(group_repr.serialize(sig[1]['QVals'][i]))
    return (sum_a, sum_b)

def calculateSigSize3(sig, group_repr):
    sum_b = 0
    for i in range(len(sig[0])):
        if isinstance(sig[0][i], bytes) or isinstance(sig[0][i], str):
            sum_b += len(sig[0][i])
        else:
            sum_b += (sig[0][i].bit_length() + 7) // 8
    sum_a = 0
    for _, elt in enumerate(sig[1]["K_0"]):
        try:
            sum_a += len(group_repr.serialize(elt))
        except:
            print(elt)
            import pdb; pdb.set_trace()
    for _,list_elts in enumerate(sig[1]["K_I"]):
        for elt in list_elts:
            try:
                sum_a += len(group_repr.serialize(elt))
            except:
                print(elt)
                import pdb; pdb.set_trace()
    return (sum_a, sum_b)

def microbenchmarks(N_ary):
    global N, TIME_SIZE_L
    pr_group = PairingGroup('BN254')
    with open(FILENAME, "w", newline="") as fileObj:
        writer = csv.writer(fileObj)
        writer.writerow(["n ary", "median sign time", "avg sign time", "median verify time", "avg verify time", "median sig. + key material size", "avg sig + key material size"])
    N = 7
    depth = int(math.ceil(80 / math.log(7, 2)))
    TIME_SIZE_L = depth
    
    ts2 = TimeDeniableSig()
    list_vals = []
    for i in range(0,500):
        beg_ticker = time.time()
        ts2.KeyGen(FAKETIMEPARAM, 256)
        total_time = time.time() - beg_ticker
        list_vals.append(total_time)
    list_vals.sort()
    middle = len(list_vals) // 2
    print("Median time for key generation is {}".format(list_vals[middle]))
    sys.exit()
    with open(FILENAME, "a", newline="") as fileObj:
        writer = csv.writer(fileObj)
        writer.writerow(["Median time for key generation is {}".format(list_vals[middle])])
    import pdb; pdb.set_trace()
    NUM_ATTEMPTS = 500
    for n in N_ary:
        # depth to achieve 2^16 values
        depth = int(math.ceil(16 / math.log(n, 2)))
        N = n
        TIME_SIZE_L = depth
        ts = TimeDeniableSig()
        vk, sk = ts.KeyGen(FAKETIMEPARAM, 256)
        tmp_res_ss = []
        tmp_res_st = []
        tmp_res_verif = []
        m1 = "HI I DON'T EFFECT MUCH NICE TO MEET YOU"
        for i in range(NUM_ATTEMPTS): 
            if i % 100 == 0:
                print("This is {}-ary try {}".format(n,i))
            rt = random.randrange(0,N**TIME_SIZE_L-1)
            beg_ticker = time.time()
            sig = ts.Sign(sk, m1, rt)
            duration = time.time() - beg_ticker
            tmp_res_st.append(duration)
            sig_size_tuple = calculateSigSize3(sig, pr_group)
            tmp_res_ss.append(sig_size_tuple[0]+sig_size_tuple[1])
            beg_ticker = time.time()
            ts.Verify(vk, sig, m1, rt)
            duration = time.time() - beg_ticker
            tmp_res_verif.append(duration)

        mid = len(tmp_res_ss) // 2
        avg_t = sum(tmp_res_st) / len(tmp_res_st)
        avg_s = sum(tmp_res_ss) / len(tmp_res_ss)
        avg_v = sum(tmp_res_verif) / len(tmp_res_verif)
        tmp_res_st.sort()
        tmp_res_ss.sort()
        tmp_res_verif.sort()
        row = [n,tmp_res_st[mid], avg_t, tmp_res_verif[mid], avg_v, tmp_res_ss[mid], avg_s] 
 
        with open(FILENAME, "a", newline="") as fileObj:
            writer = csv.writer(fileObj)
            writer.writerow(row)
        print("Finished round with {}-ary tree!".format(n))      


if __name__ == "__main__":
     
    if len(sys.argv) == 2 and sys.argv[1] == "test":
        print("Running tests...")
        logging.basicConfig(stream=sys.stderr)
        logging.getLogger("deserializer").setLevel(logging.DEBUG)
        unittest.main(argv=['first-arg-is-ignored'], exit=False)
        sys.exit(0) 
    else: 
        if len(sys.argv) > 1: 
            # this is a list of N_ary values to use with the benchmarks 
            all_ns = sys.argv[1:]
            as_nums = [int(x) for x in all_ns]
            microbenchmarks(as_nums)
        else:
            #N_ary = [6,7]
            #N_ary = [2, 5, 7, 10, 12, 14, 16, 19]
            N_ary = [2, 7, 16, 41, 256]
            microbenchmarks(N_ary)
    """ 
    ts = TimeDeniableSig()
    # I don't know what the security of the pairing scheme actually corresponds to :( 
    # according to charm, order of base field for EC used in HIBE is 512, SS = Super Singular curve -- don't know but it could be that this corresponds to 80 bits of security (1024 bit DH)
    vk, sk = ts.KeyGen(FAKETIMEPARAM, 256)
    m1 = "Cryptography rearranges power: it configures who can do what, from what."
    t1 = 16340
    median_list = [] 
    avg_time = 0
    sig = ts.Sign(sk, m1, t1)
    pr_group = PairingGroup('BN254')
    size_of_sig, size_of_enckey = calculateSigSize(sig,pr_group) 
    print("The size of the signature for this message is {} bytes and the size of the encrypted key material is {}".format(size_of_sig, size_of_enckey))
    for i in range(100):
        t1 = random.randrange(0,N**TIME_SIZE_L-1)
        sig = ts.Sign(sk, m1,t1)
        beg_ticker = time.time()
        ts.Verify(vk, sig, m1, t1)
        duration = time.time() - beg_ticker
        print(duration)
        median_list.append(duration)
        avg_time += duration
    avg_time = avg_time / 100
    median_list.sort()
    mid = len(median_list) // 2
    print("Average time for tlp parameter {} seconds was {} seconds with median time {}".format(FAKETIMEPARAM,avg_time, median_list[mid]))
    """    
