from aes_ctr import AES_CTR as ctr
from aes_cbc import AES_CBC as cbc
from eg import ECCEG as eg
from random import getrandbits, randint
from time import time
from math import log, sqrt, ceil

# Comparison of AES-CTR and EG (petlib implementation for both)

block_size = 16*1024 #block size in B, choose between 512, 4096, 16kb, 32 kb...
nb_rec = (1024**(4))/block_size #nb records in DB (needed to calculate tag size) by default 1 TB/ block size
average = 10**3 #nb of operations to do to calculate average
nb_mix = 25 # nb mixes
rounds = ceil(nb_mix * log(sqrt(nb_rec)))

print "\nstarting"

print nb_rec, block_size, nb_mix, rounds, average

print "\ninit started"

#Initiliazing AES-CTR and EG
ct=ctr() # 128 per default
cb=cbc()
e=eg() 

print "  calculating values"

toeg=[]#EG values to encrypt / randomize / decrypt
tocbc=[]

for i in range(average):
 toeg.extend([randint(1,int(log(nb_rec,2)))])
 tocbc.extend([str(getrandbits(block_size*8))])

print "init finished"

#Testing AES CTR on random value
duration_ctr = 0
for i in range(average):
 data = str(getrandbits(block_size*8)) # random value of size 512B
 time0 = time()
 ct.aes_enc_dec(data)
 time1 = time()
 duration_ctr += time1-time0 
duration_ctr = duration_ctr/average
print "aes ctr time: "+str(duration_ctr)

#Testing AES CBC encryption
duration_cbc_e = 0
for i in range(average):
 data = tocbc[i] # random value of size 512B
 time0 = time()
 b=cb.aes_enc(data)
 time1 = time()
 tocbc[i]=b
 duration_cbc_e+= time1-time0 
duration_cbc_e= duration_cbc_e/average
print "aes cbc enc time: "+str(duration_cbc_e)

#Testing AES CBC decryption
duration_cbc_d = 0
for i in range(average):
 data = tocbc[i] # random value of size 512B
 time0 = time()
 b=cb.aes_dec(data)
 time1 = time()
 tocbc[i]=b
 duration_cbc_d+= time1-time0 
duration_cbc_d = duration_cbc_d/average
print "aes cbc dec time: "+str(duration_cbc_d)

# Testing EG encryption
duration_EG_e = 0
for i in range(average):
 data = toeg[i]
 time0 = time()
 a = e.enc(data)
 time1 = time()
 toeg[i]=a
 duration_EG_e+= time1-time0 
duration_EG_e = duration_EG_e/average
print "eg enc time: "+str(duration_EG_e)

# Testing EG randomization
duration_EG_r = 0
for i in range(average):
 data = toeg[i]
 time0 = time()
 a=e.randomize(data)
 time1 = time()
 toeg[i]=a
 duration_EG_r+= time1-time0 
duration_EG_r = duration_EG_r/average
print "eg rand time: "+str(duration_EG_r)

# Testing EG decryption
duration_EG_d = 0
for i in range(average):
 data = toeg[i]
 time0 = time()
 a=e.dec(data)
 time1 = time()
 toeg[i]=a
 duration_EG_d+= time1-time0 
duration_EG_d = duration_EG_d/average
print "eg dec time: "+str(duration_EG_d)

tot = nb_rec * (duration_EG_e + duration_EG_d + (4 * duration_ctr + 2 * duration_EG_r) * rounds / nb_mix)
dec = nb_rec * duration_EG_d
print "\ntotal encryption " + str( tot - dec)+"s"
print "total decryption " + str( dec)+"s"
print "total crypt "+ str( tot)+"s"

tot_aes = (nb_rec  / nb_mix) *(4 * duration_ctr) * rounds 
print "\ntotal encryption only AES " + str( tot_aes)+"s"

print "\ntest finished"

