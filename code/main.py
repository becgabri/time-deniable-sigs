
from HIBE.hibenc_lew11 import HIBE_LW11 
import timelockpuzzle
import math

# this is the size of time stamps supported
TIME_SIZE_L = 4


def FSDelegate(pk, t, sk_t, t_prime):
    _, list_sk_t = sk_t 
    new_list = [] 
    return

def FSKeygen(sk_prime, t):
    pk, sk = sk_prime 
    list_keys = []
    t_as_bits = bin(t)[2:].zfill(TIME_SIZE_L) 
    find_right = False
    for i in range(len(t_as_bits)):
        curr_slice = t_as_bits[:len(t_as_bits)-1*i]
        is_LC = True if (curr_slice[len(curr_slice)-1] == '0') else False
        if is_LC and not find_right:
            #deleg_key = HIBE_LW11.keyGen(curr_slice, sk, pk)
            list_keys.append(curr_slice)
            find_right = True
        elif find_right and not is_LC: # means right child
            # take the left child of your parent
            identity = curr_slice[:-1] + '0'
            #deleg_key = HIBE_LW11.keyGen(identity, sk, pk)
            list_keys.append(identity)
        elif len(curr_slice) == 1 and not is_LC:
            #deleg_key = HIBE_LW11.keyGen('0', sk, pk)
            list_keys.append('0')  
    return list_keys 


class TimeDeniableSig:

    def KeyGen(self, timeGap, secParam):
        return
 
    def Sign(sk, m, t):
        # produce the signature on the message using the FS
        pk_prime, sk_prime = sk
        
        list_keys = FSKeygen(sk, t)    
        # time lock encrypt the functional key 
        return

    def AltSign(vk, m_0, t_0, sigma_0, m, t):
        return

    def Verify(vk, sigma, m, t):
        return

if __name__ == "__main__":
    print("Trying to build a thing")
    # this is just simple testing 
