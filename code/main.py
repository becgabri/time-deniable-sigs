 
from HIBE.hibenc_lew11 import HIBE_LW11 
import timelockpuzzle.puzzle as puzzle 
import math
import json
from json import JSONEncoder, JSONDecoder
from charm.toolbox.pairinggroup import GT, PairingGroup 

# this is the size of time stamps supported
TIME_SIZE_L = 4
MACHINE_SPEED = 10 # this should be the number of squarings a machine can do per second

# It's expected that id here is a binary string 
def encodeIdentity(id):
    list_id = []
    curr_id = ""
    for _, val in enumerate(id):
        curr_id += val
        list_id.append(curr_id)
    return list_id

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

class KeyEncoder(JSONEncoder):
    def default(self, o):
        group = PairingGroup('SS512')
 
        if isinstance(o, bytes):
            return o.decode()
        if group.ismember(o):
            return group.serialize(o)
        ValueError("Unexpected element in key encoder, please debug :(")

class KeyDecoder(JSONDecoder):
    def __init__(self,*args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs) 

    def object_hook(self, obj):
        group = PairingGroup('SS512')
        if isinstance(obj, dict):
            for i,val in obj.items():
                if isinstance(val, list):
                    for i2, val2 in enumerate(val):
                        for i3, val3 in enumerate(val2):
                            pairing_elt = group.deserialize(val3.encode())
                            obj[i][i2][i3] = pairing_elt
        return obj
    
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

        # if there are keys before the prefix point, just randomize and keep those
        for i in range(idx_for_prefix):
            new_list.append((list_sk_t[i][0], self.hibe.delegate(pk, list_sk_t[i][1], encodeIdentity(list_sk_t[i][0]))))

        # take the prefix and delegate off of what needs to be delegated
        # this time, we go from the direction of "root" down to the leaf because in this context that makes more sense
        t_prime_as_bits = bin(t_prime)[2:].zfill(TIME_SIZE_L)
        curr_id = list_sk_t[idx_for_prefix][0]
        curr_id = curr_id[:len(curr_id)-1]

        for i in range(idx_for_prefix, TIME_SIZE_L-1):
            string_left_mask = (1 << (TIME_SIZE_L-i-1)) -1
            if t_prime_as_bits[i] == '0' and int(t_prime_as_bits[i+1:],2) == string_left_mask:
                # problem, probably have to call delegate multiple times here :( 
                curr_key = list_sk_t[idx_for_prefix][1]
                idAsEncoded = encodeIdentity(curr_id+'0')
                for j in range(i-prefix_len):
                    curr_key = self.hibe.delegate(pk, curr_key, idAsEncoded[:prefix_len+j+1])
                new_list.append((curr_id + '0', self.hibe.delegate(pk, curr_key, idAsEncoded)))
                return new_list
            elif t_prime_as_bits[i] == '1' and i != (TIME_SIZE_L - 1):
                curr_key = list_sk_t[idx_for_prefix][1]
                idAsEncoded = encodeIdentity(curr_id+'0')
                for j in range(i-prefix_len):
                    curr_key = self.hibe.delegate(pk, curr_key, idAsEncoded[:prefix_len+j+1])
                new_list.append((curr_id + '0', self.hibe.delegate(pk, curr_key, idAsEncoded)))

            curr_id += t_prime_as_bits[i]

        if t_prime_as_bits[TIME_SIZE_L-1] == '0' and t_prime < t: 
            len_size = TIME_SIZE_L - len(list_sk_t[idx_for_prefix][0])
            curr_key = list_sk_t[idx_for_prefix][1]
            idAsEncoded = encodeIdentity(t_prime_as_bits)
            for i in range(len_size):
                curr_key = self.hibe.delegate(pk, curr_key, idAsEncoded[:prefix_len+1+i])
            new_list.append((t_prime_as_bits, curr_key)) 

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

        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)
        encedID = encodeIdentity(t_bin+m)
        curr_key = list_keys[idx][1]
        for j in range(len(encedID)-lenPrefix):
            curr_key = self.hibe.delegate(pk_prime, curr_key, encedID[:lenPrefix+j+1])  
        return curr_key

    # assumption right now is message is a binary string 
    def Sign(self, sk, m, t):
        # produce the signature on the message using the FS
        pk_prime, timeGap, sk_prime = sk
        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)

        list_keys = self.FSKeygen((pk_prime, sk_prime), t)
        s = self.FSSign((pk_prime, list_keys), t, m)
        
        #TODO: time lock encrypt the functional key 
        import pdb; pdb.set_trace()
        pt_str = json.dumps(list_keys,cls=KeyEncoder)
        pt = pt_str.encode()
        _, _, n, a, bar_t, enc_key, enc_msg, _ = puzzle.encrypt(pt, timeGap, MACHINE_SPEED)
        return ((n,a,bar_t,enc_key, enc_msg), s)

    def AltSign(self, vk, m_0, t_0, sigma_0, m, t):
        if t > t_0: 
            raise ValueError("Cannot sign a message on a later timestamp with a key for an earlier one!")
        pk, timeGap = vk

        c, _ = sigma_0 
        n, a, bar_t, enc_key, enc_msg = c 
        keys_as_bytes = puzzle.decrypt(n, a, bar_t, enc_key, enc_msg)
        list_keys = json.loads(keys_as_bytes.decode(), cls=KeyDecoder)
        import pdb; pdb.set_trace() 
        # need to shrink w/ FS DELEG
        new_list_keys = self.FSDelegate(pk, t_0, (pk, list_keys), t)
        s = self.FSSign((pk, new_list_keys), t, m)
        
        pt = json.dumps(new_list_keys, cls=KeyEncoder).encode()
        _, _, n, a, bar_t, enc_key, enc_msg, _ = puzzle.encrypt(pt, timeGap, MACHINE_SPEED)
        return ((n,a,bar_t,enc_key,enc_msg), s)

    #it's assumed m is a bit string, t is a numerical value
    def Verify(self, vk, sigma, m, t):
        pk,_ = vk
        _, sk_id = sigma
        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)

        test_elt = self.group.random(GT)
        # encrypt/decrypt check -- problem(!) think this has to be a Group elt. in target group G_T
        ct = self.hibe.encrypt(test_elt, encodeIdentity(t_bin+m), pk)

        if self.hibe.decrypt(ct, sk_id) == test_elt:
            return True
        return False

def deepEqual(list1, list2): 
    if len(list1) != len(list2):
        return False
    for i,val in enumerate(list1):
        if val != list2[i]:
            return False
    return True

if __name__ == "__main__":
    ts = TimeDeniableSig()
    
    fakeTimeParam = 20
    # I don't know what the security of the pairing scheme actually corresponds to :( 
    # according to charm, order of base field for EC used in HIBE is 512, SS = Super Singular curve -- don't know if this corresponds to AES key strength 256
    vk, sk = ts.KeyGen(fakeTimeParam, 256)

    pk, timeGap, msk = sk 
    keys = ts.FSKeygen((pk,msk), 4)

    m = bin(12)[2:].zfill(4) 
    
    sig = ts.Sign(sk, m, 14)

    if not ts.Verify(vk, sig, m, 14):
        print("Verification failed")

    m2 = bin(15).zfill(4)
    t2 = 6
    sig2 = ts.AltSign(vk, m, 14, sig, m2, t2)

    if not ts.Verify(vk, sig2, m2, t2):
        print("Verification failed")

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
