'''
Shorter IBE and Signatures via Asymmetric Pairings
  
| From: "J. Chen, H. Lim, S. Ling, H. Wang, H. Wee Shorter IBE and Signatures via Asymmetric Pairings", Section 4.
| Published in: Pairing 2012
| Available from: http://eprint.iacr.org/2012/224
| Notes: This is a shorter IBE construction based on SXDH construction.

* type:           encryption (identity-based)
* setting:        bilinear groups (asymmetric)

:Authors:    Fan Zhang(zfwise@gwu.edu), supported by GWU computer science department
:Date:       3/2013
:Note: The implementation is different from what the paper described. 
       Generally speaking,  instead of storing msk= { \alpha, g_2^{d_1^*}, g_2^{d_2^*} } as the master secret key, 
       we stored \msk= \{ \alpha, d_1^*, d_2^* \}. And for the computation of sk_id, we first compute 
       (\alpha + r ID)d_1^* - r \d_2^*$ then apply the exponential operation. This reduce the G2 exponentials from 8 to 4. 
       This is the same trick we used in improving N04(Waters05) scheme.

Modifier: Gabrielle Beck (becgabri@jhu.edu)
Date: 12/13/2022
Note This is an implementation of the HIBE scheme presented in Appendix A of the aforementioned paper

'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.matrixops import *
from charm.core.crypto.cryptobase import *
import copy

debug = False
class HIBE_CLLWW12:
    """
    >>> group = PairingGroup('MNT224', secparam=1024)    
    >>> ibe = IBE_Chen12_z(group)
    >>> (master_public_key, master_secret_key) = ibe.setup()
    >>> ID = 'user@email.com'
    >>> private_key = ibe.extract(master_secret_key, ID)
    >>> msg = group.random(GT)
    >>> cipher_text = ibe.encrypt(master_public_key, ID, msg)
    >>> decryptedMSG = ibe.decrypt(master_public_key, private_key, cipher_text)
    >>> print (decryptedMSG==msg)
    True
    """
    def __init__(self, groupObj):
        global group
        group = groupObj

    # build_ds has each vector as a *row* vector
    # transposed_mtx needs to be transposed to be correct
    def createOrthoBases(self,dim,embed_val):
        build_ds = []
        for i in range(dim):
            new_dim = []
            for j in range(dim):
                new_dim.append(group.random(ZR))
            build_ds.append(new_dim)
        transposed_mtx = []
        col_inv = []
        for i in range(dim):
            col_inv.append(group.init(ZR))
    
        for i in range(dim):
            build_ds[i].append(group.init(ZR,0))
        for i in range(dim):
            #step 1: rebuild the old matrix
            new_build = copy.copy(build_ds) 
            new_build[i][-1] = embed_val
            if i > 0:
                new_build[i-1][-1] = group.init(ZR,0)
            col_inv = GaussEliminationinGroups(new_build)
            transposed_mtx.append(col_inv)
        # remove "dead rows" from build_ds and then return
        for i in range(dim):
            build_ds[i].pop()
        return build_ds,transposed_mtx

    def setup(self, depth):
        g1 = group.random(G1)
        g2 = group.random(G2)
        random_val = group.random(ZR)
        print("Random Value is {}".format(random_val))
        D0, D0_Inv = self.createOrthoBases(3, random_val)
        t5 = group.init(ZR,0)
        for i in range(3):
            t5 += D0[0][i] * D0_Inv[1][i]
        print("SHOULD BE ZERO IS {}".format(t5))
        g1d10 = (g1**D0[0][0] , g1**D0[0][1] , g1**D0[0][2])
        g1d30 = (g1**D0[2][0], g1**D0[2][1], g1**D0[2][2])
        g2d10_dual = (g2**D0_Inv[0][0], g2**D0_Inv[0][1], g2**D0_Inv[0][2])
        target_elt = pair(g1, g2)**random_val
        print("Target elt: {}".format(target_elt))
        print("First check")
        sum_d10_w_dual = group.init(ZR,0)
        for i in range(3):
            sum_d10_w_dual += D0[0][i] * D0_Inv[0][i]
        print("Sum result is {}".format(sum_d10_w_dual))
        print("Second Check")
        sum_out = pair(g1d10[0], g2d10_dual[0])
        for i in range(2):
            sum_out *= pair(g1d10[1+i], g2d10_dual[1+i])
        print("Should be target elt: {}".format(sum_out))
    
        pk = { "g1": g1, "gT": target_elt, "g1d10": g1d10, "g1d30": g1d30, "g1di_comps": [], "g2d10_d": g2d10_dual, "g2di_d_comps": []} 
        # sample depth-dependent orthonormal bases
        di_d_comps = []
        for i in range(depth):
            DI, DI_Inv = self.createOrthoBases(4, random_val)
            g1d1i = (g1**DI[0][0], g1**DI[0][1], g1**DI[0][2], g1**DI[0][3])
            g1d2i = (g1**DI[1][0], g1**DI[1][1], g1**DI[1][2], g1**DI[1][3])
            g2d1i_dual = (g2**DI_Inv[0][0], g2**DI_Inv[0][1], g2**DI_Inv[0][2], g2**DI_Inv[0][3])
            g2d2i_dual = (g2**DI_Inv[1][0], g2**DI_Inv[1][1], g2**DI_Inv[1][2], g2**DI_Inv[1][3])
            d1i_d = (DI_Inv[0][0], DI_Inv[0][1], DI_Inv[0][2], DI_Inv[0][3])
            d2i_d = (DI_Inv[1][0], DI_Inv[1][1], DI_Inv[1][2], DI_Inv[1][3])
            di_d_comps.append((d1i_d, d2i_d))
            pk["g1di_comps"].append((g1d1i, g1d2i))
            pk["g2di_d_comps"].append((g2d1i_dual, g2d2i_dual))
        # test cond
        """
        print("DEBUG SETUP")
        t1 = pair(g1d10[0],g2d10_dual[0])
        for i in range(2):
            t1 *= pair(g1d10[i+1], g2d10_dual[i+1])
        print("SHOULD BE TARGET {}".format(target_elt))
        t1 = pair(g1d30[0],g2d10_dual[0])
        for i in range(2):
            t1 *= pair(g1d30[i+1], g2d10_dual[i+1])
        print("SHOULD BE ONE {}. Is it? {}".format(t1, t1 == group.init(GT,1)))
        """
        msk = {
                'g2':g2, 
                'd10_d': (D0_Inv[0][0], D0_Inv[0][1], D0_Inv[0][2]), 
                'd30_d': (D0_Inv[2][0], D0_Inv[2][1], D0_Inv[2][2]),
                'di_d_comps': di_d_comps,
               }
        t3 = msk['d30_d'][0]*D0[0][0]
        for i in range(2):
            t3 += msk['d30_d'][i+1]*D0[0][i+1]
        print("DEBUG: SHOULD BE 0 IS {}".format(t3))
        if(debug):
            print("Public parameters...")
            group.debug(pk)
            print("Secret parameters...")
            group.debug(msk)
        return (msk, pk)

    def keyGen(self, I, MSK, PP):    
        num_levels = len(I)
        r = []
        s = []
        s_0 = group.init(ZR, 0)
        for i in range(num_levels):
            r.append(group.random(ZR))
            s.append(group.random(ZR))
            s_0 += s[-1]
        exp1 = [(-s_0) * MSK['d10_d'][i] + MSK['d30_d'][i] for i in range(3)] 
        first_key_comp = tuple([MSK['g2']**exp1[i] for i in range(3)])
        #first_key_comp = (MSK['g2']**((-s_0) * MSK['d10_d'][0] + MSK['d30_d'][0]), MSK['g2']**((-s_0) * MSK['d10_d'][1] + MSK['d30_d'][1]), MSK['g2']**((-s_0) * MSK['d10_d'][2] + MSK['d30_d'][2]))
        leveled_key_comp = []
        for i in range(num_levels):
           id_i = group.hash(I[i], ZR)
           exponent = [s[i] * MSK['di_d_comps'][i][0][j] + (r[i] * (id_i * MSK['di_d_comps'][i][0][j] - MSK['di_d_comps'][i][1][j])) for j in range(4)]
           leveled_key_comp.append((MSK['g2']**exponent[0], MSK['g2']**exponent[1], MSK['g2']**exponent[2], MSK['g2']**exponent[3]))
        s.append(s_0)
        print("Adding s_0: {}".format(s_0))
        return {"K_0": first_key_comp, "K_I": leveled_key_comp}, s #TODO REMOVE THE BAD SHIT 

    def delegate(self, PP, SK, I):
        num_levels = len(I)
        old_num = len(SK["K_I"])
        r = []
        s = []
        s_0 = group.init(ZR, 0)
        for i in range(num_levels):
            r.append(group.random(ZR))
            s.append(group.random(ZR))
            s_0 += s[-1]
        neg_one = group.init(ZR,-1)
        # update first key component in the beginning
        new_first_key = ((SK['K_0'][0]*PP['g2d10_d'][0])**(neg_one*s_0), (SK['K_0'][1]*PP['g2d10_d'][1])**(neg_one*s_0), (SK['K_0'][2]*PP['g2d10_d'][2])**(neg_one*s_0))
        new_level_comps = []
        for i in range(num_levels):
            id_i = group.hash(I[i], ZR)
            new_comp = [PP["g2di_d_comps"][i][0][j]**(s[i] + r[i]*id_i) / PP["g2di_d_comps"][i][1][j]**(r[i]) for j in range(4)] 
            if i < old_num:
                for j in range(4):
                    new_comp[j] *= SK['K_I'][i][j]
            new_level_comps.append(tuple(new_comp))
        return {"K_0": new_first_key, "K_I": new_level_comps}
    
    def encrypt(self, M, I, PP):
        z, z_0 = group.random(ZR), group.random(ZR)
        c = M * PP["gT"]**z
        c_0 = (PP["g1d10"][0]**z_0 * PP["g1d30"][0]**z, PP["g1d10"][1]**z_0 * PP["g1d30"][1]**z, PP["g1d10"][2]**z_0 * PP["g1d30"][2]**z)
        c_i = []
        num_levels = len(I)
        for i in range(num_levels):
            id_i = group.hash(I[i], ZR)
            c_i.append((PP["g1di_comps"][i][0][0]**z_0 * PP["g1di_comps"][i][1][0]**(id_i*z_0),
                    PP["g1di_comps"][i][0][1]**z_0 * PP["g1di_comps"][i][1][1]**(id_i*z_0),
                    PP["g1di_comps"][i][0][2]**z_0 * PP["g1di_comps"][i][1][2]**(id_i*z_0),
                    PP["g1di_comps"][i][0][3]**z_0 * PP["g1di_comps"][i][1][3]**(id_i*z_0)))
        print("FOR DECRYPTION CHECK -- C0")
        if len(s) != num_levels+1:
            print("I made an error :( ")
        print("s[0] is supposedly {}".format(s[num_levels]))    
        val_n = PP["gT"]**((-s[num_levels])*z_0 + z)
        print("{}".format(val_n))
        print("FOR DECRYPTION CHECK -- LEVELS")
        for i in range(num_levels):
            elt_gT = PP["gT"]**(s[i]*z_0)
            print("For level {} element is {}".format(i, elt_gT))
        return {"C": c, "C_0": c_0, "C_I": c_i}
    
    def decrypt(self, CT, SK):
        elt_m = pair(CT["C_0"][0], SK["K_0"][0])
        for i in range(2):
            elt_m *= pair(CT["C_0"][1+i], SK["K_0"][1+i])
        print("DEBUG DECRYPTION CHECK -- C0 {}".format(elt_m))
        id_len = len(SK["K_I"])
        for i in range(id_len):
            elt_j = pair(CT["C_I"][i][0], SK["K_I"][i][0])
            for j in range(3):
                elt_j *= pair(CT["C_I"][i][j+1], SK["K_I"][i][j+1])
            print("DEBUG DECRYPTION CHECK for level {} element is {}".format(i, elt_j))
            elt_m *= elt_j
        M = CT["C"] / elt_m
        return M

def main():

    group = PairingGroup('MNT224', secparam=1024)    
    msg = group.random(GT)
    print("Message to encrypt:")
    print(msg)
    I = [".gr.edu.mmlab"]
    I2 = [".gr.edu.mmlab","mail"]
    I3 = [".gr.edu.mmlab","mail", "fotiou"]
    hibe  = HIBE_CLLWW12(group)
    (MSK,PP) = hibe.setup(4)
   
    print("Got through encryption")
    SK3_pr, S = hibe.keyGen(I3, MSK, PP)
    global s
    s = S
    CT = hibe.encrypt(msg,I3,PP)
    M = hibe.decrypt(CT, SK3_pr)
    print(M)
    """
    SK = hibe.keyGen(I,MSK,PP)
    print("Got through key generation")
    SK2 = hibe.delegate(PP,SK, I2)
    print("Got through one key delegate")
    SK3 = hibe.delegate(PP,SK2, I3)
    print("Got through second delegation")
    M = hibe.decrypt(CT, SK3)
    print("Decrypted message with ID3:")
    print(M)
    M = hibe.decrypt(CT, SK2)
    print("Decrypted message with ID2:")
    print(M)
    M = hibe.decrypt(CT, SK)
    print("Decrypted message with ID1:")
    print(M)
    """

if __name__ == '__main__':
    debug = True
    main()   

