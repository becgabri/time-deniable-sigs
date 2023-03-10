# time-deniable-sigs

This is an impelementation of Time Deniable Signatures. The construction uses a key-indistinguishable HIBE and a RSW based time lock scheme. The key-indist. HIBE can be one of the following: a variant of Gentry-Silverberg, a variant of the prime order translation of Lewko-Waters, or the HIBE of CLLWW12. 

This codebase utilizes [charm](https://github.com/JHUISI/charm) and requires it to be installed. Charm has dependencies on GMP, PBC, and Openssl. Instructions for installation can be found [here](https://github.com/JHUISI/charm/blob/dev/INSTALL).   

The main code of main.py in code/ currently produces benchmarks for N in the ranges specified in the paper.  
