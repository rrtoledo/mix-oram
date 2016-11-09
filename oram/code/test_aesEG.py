from aes_ctr import AES_CTR as ctr
from aes_cbc import AES_CBC as cbc
from eg import ECCEG as eg
from random import getrandbits, randint
from time import time
from math import log, sqrt, ceil
from datetime import datetime, timedelta

# Comparison of AES-CTR and EG (petlib implementation for both)

block_size = 4*1024 #block size in B, choose between 512, 4096, 16kb, 32 kb...
nb_rec = (1024**(3))/block_size #nb records in DB (needed to calculate tag size) by default 1 GB/ block size
average = 10**4 #nb of operations to do to calculate average
nb_mix = 3 # nb mixes
rounds = ceil((nb_mix/2) * log(sqrt(nb_rec)))

print "\nstarting"

print nb_rec, block_size, nb_mix, rounds, average

print "\ninit started"

#Initiliazing AES-CTR and EG
ct=ctr() # 128 per default
cb=cbc()

print "  calculating values"

tocbc=[]
toctr=[]

for i in range(average):
 tocbc.extend([str(getrandbits(block_size*8))])
 toctr.extend([str(getrandbits(block_size*8))])

print "init finished"

#Testing AES CTR on random value
duration_ctr = 0
for i in range(average):
 data = toctr[i]
 time0 = time()
 ct.aes_enc_dec(data)
 time1 = time()
 duration_ctr += time1-time0 
duration_ctr = 1.0*duration_ctr/average
print "aes ctr time: "+str(duration_ctr)

#Testing AES CBC encryption
duration_cbc_e = 0
for i in range(average):
 data = tocbc[i] # random value of size 512B
 time0 = time()
 b=cb.aes_enc_dec(data)
 time1 = time()
 tocbc[i]=b
 duration_cbc_e+= time1-time0 
duration_cbc_e= 1.0*duration_cbc_e/average
print "aes cbc enc time: "+str(duration_cbc_e)

#Testing AES CBC decryption
duration_cbc_d = 0
for i in range(average):
 data = tocbc[i] # random value of size 512B
 time0 = time()
 b=cb.aes_enc_dec(data)
 time1 = time()
 tocbc[i]=b
 duration_cbc_d+= time1-time0 
duration_cbc_d = 1.0*duration_cbc_d/average
print "aes cbc dec time: "+str(duration_cbc_d)

tot = nb_rec * 2* (rounds +nb_mix) * duration_ctr
print "total crypt ctr "+ str( tot)+"s"+" with in total "+ str(2* (rounds +nb_mix))+ " rounds"
d = datetime(1,1,1) + timedelta(seconds=tot)
print("DAYS:HOURS:MIN:SEC")
print("%d:%d:%d:%d" % (d.day-1, d.hour, d.minute, d.second))

tot_cbc = nb_rec  *2* rounds * duration_cbc_e
print "\ntotal crypt cbc " + str( tot_cbc)+"s" +" with in total "+ str(2* (rounds))+ " rounds"
d2 = datetime(1,1,1) + timedelta(seconds=tot_cbc)
print("DAYS:HOURS:MIN:SEC")
print("%d:%d:%d:%d" % (d2.day-1, d2.hour, d2.minute, d2.second))

print "\ntest finished"

