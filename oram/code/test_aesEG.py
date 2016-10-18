from aes_ctr import AES_CTR as aes
from eg import ECCEG as eg
from random import getrandbits, randint
from time import time
from math import log

# Comparison of AES-CTR and EG (petlib implementation for both)
nb_rec = 10**4 #nb records in DB (needed to calculate tag size)
average = 10**5 #nb of operations to do to calculate average

#Initiliazing AES-CTR and EG
a=aes() # 128 per default
e=eg() 

#EG values to encrypt / randomize / decrypt
toeg=[]

for i in range(average):
 toeg.extend([randint(1,int(log(nb_rec,2)))])

#Testing AES on random value
duration = 0
for i in range(average):
 data = str(getrandbits(512*8)) # random value of size 512B
 time0 = time()
 a.aes_enc_dec(data)
 time1 = time()
 duration+= time1-time0 

print "aes enc/dec time: "+str(duration/average)

# Testing EG encryption
duration = 0
for i in range(average):
 data = toeg[i]
 time0 = time()
 a = e.enc(data)
 time1 = time()
 toeg[i]=a
 duration+= time1-time0 

print "eg enc time: "+str(duration/average)

# Testing EG randomization
duration = 0
for i in range(average):
 data = toeg[i]
 time0 = time()
 a=e.randomize(data)
 time1 = time()
 toeg[i]=a
 duration+= time1-time0 

print "eg rand time: "+str(duration/average)

# Testing EG decryption
duration = 0
for i in range(average):
 data = toeg[i]
 time0 = time()
 a=e.dec(data)
 time1 = time()
 toeg[i]=a
 duration+= time1-time0 

print "eg dec time: "+str(duration/average)

