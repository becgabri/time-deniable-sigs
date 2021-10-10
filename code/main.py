 
from HIBE.hibenc_lew11 import HIBE_LW11 
import timelockpuzzle
import math
from charm.toolbox.pairinggroup import GT, PairingGroup 

# this is the size of time stamps supported
TIME_SIZE_L = 5

# It's expected that id here is a binary string 
def encodeIdentity(id):
    list_id = []
    curr_id = ""
    for _, val in enumerate(id):
        curr_id += val
        list_id.append(curr_id)
    return list_id

# this is just a placeholder for now
def randomizeKey(sk): 
     return sk

def findPrefix(list_sk_t, t_prime):
    t_prime_bin = bin(t_prime)[2:].zfill(TIME_SIZE_L)

    # start search halfway through list -- this is basically binary search
    beg = 0
    end = len(list_sk_t)
    
    while True:
        curr_idx = int(math.floor((end + beg) / 2))
        prefix_cut = t_prime_bin[:len(list_sk_t[curr_idx])+1]
        if t_prime_bin.startswith(list_sk_t[curr_idx][0]):
            # end condition
            return curr_idx
        elif int(prefix_cut,2) > int(list_sk_t[curr_idx][0], 2):
            beg = curr_idx
        else:
            end = curr_idx
    
class TimeDeniableSig:

    def KeyGen(self, timeGap, secParam):
        # this is the easiest one, just the 
        self.group = PairingGroup('SS512')
        self.hibe = HIBE_LW11(self.group)
                
        msk, pp = self.hibe.setup()
        return ((pp,timeGap), (pp,timeGap,msk))


    def FSDelegate(self, pk, t, sk_t, t_prime):
        _, list_sk_t = sk_t 
        new_list = []
        #find prefix using binary search 
        idx_for_prefix = findPrefix(list_sk_t, t_prime)


        # if there are keys before the prefix point, just randomize and keep those
        for i in range(idx_for_prefix):
            new_list.append(randomizeKey(list_sk_t[i])) # TODO: check if the HIBE scheme impl can already properly deal with this

        # take the prefix and delegate off of what needs to be delegated
        # this time, we go from the direction of "root" down to the leaf because in this context that makes more sense
        t_prime_as_bits = bin(t_prime)[2:].zfill(TIME_SIZE_L)
        curr_id = list_sk_t[idx_for_prefix]
        curr_id = curr_id[:len(curr_id)-1]
        for i in range(idx_for_prefix, TIME_SIZE_L-1):
            string_left_mask = (1 << (TIME_SIZE_L-i-1)) -1
            if t_prime_as_bits[i] == '0' and int(t_prime_as_bits[i+1:],2) == string_left_mask:
                new_list.append(curr_id + '0')
                return new_list
            elif t_prime_as_bits[i] == '1' and i != (TIME_SIZE_L - 1):
                new_list.append(curr_id+'0')

            curr_id += t_prime_as_bits[i]

        if t_prime_as_bits[TIME_SIZE_L-1] == '0' and t_prime < t: 
            new_list.append(t_prime_as_bits) 

        return new_list

    # going down from the root
    def FSKeygen(self, sk_prime, t):
        pk, sk = sk_prime 
        list_keys = []
        t_as_bits = bin(t)[2:].zfill(TIME_SIZE_L) 
        curr_id = ''

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

    # assumption right now is message is a binary string 
    def Sign(self, sk, m, t):
        # produce the signature on the message using the FS
        pk_prime, timeGap, sk_prime = sk
        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)

        list_keys = self.FSKeygen((pk_prime, sk_prime), t)
        idx = findPrefix(list_keys, t)
        # extract key and run hibe delegate to get the signature
        #TODO: change to a hash 
        lenPrefix = len(list_keys[idx][0])
        
        # so yeah... this is going to suck
        # need to delegate for everything leftover here :(         
        encedID = encodeIdentity(t_bin+m)
        curr_key = list_keys[idx][1]
        for j in range(len(encedID)-lenPrefix):
            curr_key = self.hibe.delegate(pk_prime, curr_key, encedID[:lenPrefix+j+1])  
        
        """
        leftover_t = ""
        if lenPrefix != len(t_bin):
            leftover_t = t_bin[lenPrefix+1:]
       
        id_to_extract = [t_bin[:lenPrefix+1], leftover_t+m]
        

        # this is a temporary check, pull this out in a sec
        if not (id_to_extract[0]+id_to_extract[1]).startswith(list_keys[idx][0]):
            print("Still failed :(")
            import pdb; pdb.set_trace()
        sigma = self.hibe.delegate(pk_prime, list_keys[idx][1], id_to_extract) 
        """
        # time lock encrypt the functional key 
        return curr_key

    def AltSign(self, vk, m_0, t_0, sigma_0, m, t):
        return

    #it's assumed m is a bit string, t is a numerical value
    def Verify(self, vk, sigma, m, t):
        pk,_ = vk
        t_bin = bin(t)[2:].zfill(TIME_SIZE_L)

        test_elt = self.group.random(GT)
        # encrypt/decrypt check -- problem(!) think this has to be a Group elt. in target group G_T
        ct = self.hibe.encrypt(test_elt, encodeIdentity(t_bin+m), pk)

        if self.hibe.decrypt(ct, sigma) == test_elt:
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
    
    fakeTimeParam = 0
    # I don't know what the security of the pairing scheme actually corresponds to :( 
    # according to charm, order of base field for EC used in HIBE is 512, SS = Super Singular curve -- don't know if this corresponds to AES key strength 256
    vk, sk = ts.KeyGen(fakeTimeParam, 256)
    #m = bin(7482954207589427489323078107389174891)[2:].zfill(256)
    m = bin(5)[2:].zfill(4) 
    if len(m) > 256:
        print("I messed up")
        import pdb; pdb.set_trace()

    sig = ts.Sign(sk, m, 12)

    if not ts.Verify(vk, sig, m, 12):
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
