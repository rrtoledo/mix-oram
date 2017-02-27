from mix import Mix
from cclient import Client
from db import DB
import base64
import math
from petlib.cipher import Cipher 
from hashlib import sha512
from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
from os import urandom

import pytest

def test_aes_enc_dec():

	aes = Cipher("AES-128-CTR")
	key = urandom(16)
	iv = urandom(16)
	enc = aes.enc(key, iv)
	ipt = "Hello"

	ciphertext = enc.update(ipt)
	ciphertext += enc.finalize()

	dec = aes.enc(key, iv)
	plaintext = dec.update(ciphertext)
	plaintext += dec.finalize()

	assert ipt == plaintext


def test_permutation():


	m1 = Mix("M1", "localhost", 8001, 0, 0, 0)
	
	seed=urandom(16)
	data=[]
	for i in range(9):
		data.extend([str(i)*4])
	
	permuted = m1.permute(seed, data, 0)
	permuted = m1.permute(seed, permuted, 1)

	assert data == permuted



def test_sort():
	m1 = Mix("M1", "localhost", 8001, 0, 0, 0)
	m1.records=9
	m1.list=[]
	for i in range(3):
		m1.list.extend([i])
	m1.index=0

	m2 = Mix("M2", "localhost", 8002, 0, 0, 0)
	m2.records=9
	m2.list=[]
	for i in range(3):
		m2.list.extend([i])
	m2.index=1

	m3 = Mix("M3", "localhost", 8003, 0, 0, 0)
	m3.records=9
	m3.list=[]
	for i in range(3):
		m3.list.extend([i])
	m3.index=2

	pubseed= urandom(16)
	nbmix=3
	data1=[]
	for i in range(3):
		data1.extend([str(i)*4])
	data2=[]
	for i in range(3):
		data2.extend([str(i+3)*4])
	data3=[]
	for i in range(3):
		data3.extend([str(i+2*3)*4])
	
	alloc1 = m1.permute_global(pubseed, 9, nbmix, 1)
	sortout1 = m1.sort_global_out(data1, alloc1)
	
	alloc2 = m2.permute_global(pubseed, 9, nbmix, 1)
	sortout2 = m2.sort_global_out(data2, alloc2)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 1)
	sortout3 = m3.sort_global_out(data3, alloc3)


	received1=[sortout1[0], sortout2[0], sortout3[0]]
	received2=[sortout1[1], sortout2[1], sortout3[1]]
	received3=[sortout1[2], sortout2[2], sortout3[2]]

	alloc1 = m1.permute_global(pubseed, 9, nbmix, 1)
	sortin1 = m1.sort_global_in(received1, alloc1)
	
	alloc2 = m2.permute_global(pubseed, 9, nbmix, 1)
	sortin2 = m2.sort_global_in(received2, alloc2)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 1)
	sortin3 = m3.sort_global_in(received3, alloc3)

	alloc1 = m1.permute_global(pubseed, 9, nbmix, 0)
	sortout1 = m1.sort_global_out(sortin1, alloc1)

	alloc2 = m2.permute_global(pubseed, 9, nbmix, 0)
	sortout2 = m2.sort_global_out(sortin2, alloc2)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 0)
	sortout3 = m3.sort_global_out(sortin3, alloc3)

	received1=[sortout1[0], sortout2[0], sortout3[0]]
	received2=[sortout1[1], sortout2[1], sortout3[1]]
	received3=[sortout1[2], sortout2[2], sortout3[2]]

	alloc1 = m1.permute_global(pubseed, 9, nbmix, 0)
	sortin1 = m1.sort_global_in(received1, alloc1)

	alloc2 = m2.permute_global(pubseed, 9, nbmix, 0)
	sortin2 = m2.sort_global_in(received2, alloc2)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 0)
	sortin3 = m3.sort_global_in(received3, alloc3)


	data = []
	for i in range(9):
		data.append(str(i)*4)
	res = []
	for i in range(len(sortin1)):
		res.append(sortin1[i])
	for i in range(len(sortin2)):
		res.append(sortin2[i])
	for i in range(len(sortin3)):
		res.append(sortin3[i])

	print "res", res
	print "data", data

	assert data == res

def test_sortpermuteandencrypt():
	m1 = Mix("M1", "localhost", 8001, 0, 0, 0)
	m1.records=9
	m1.list=[]
	for i in range(3):
		m1.list.extend([i])
	m1.index=0

	m2 = Mix("M2", "localhost", 8002, 0, 0, 0)
	m2.records=9
	m2.list=[]
	for i in range(3):
		m2.list.extend([i])
	m2.index=1

	m3 = Mix("M3", "localhost", 8003, 0, 0, 0)
	m3.records=9
	m3.list=[]
	for i in range(3):
		m3.list.extend([i])
	m3.index=2

	pubseed= urandom(16)
	pubseed2 = urandom(16)
	seed1= urandom(16)
	seed2 = urandom(16)
	seed3 = urandom(16)
	key1= urandom(16)
	key2 = urandom(16)
	key3 = urandom(16)
	iv1= urandom(16)
	iv2 = urandom(16)
	iv3 = urandom(16)

	nbmix=3
	data1=[]
	for i in range(3):
		data1.extend([str(i)*4])
	data2=[]
	for i in range(3):
		data2.extend([str(i+3)*4])
	data3=[]
	for i in range(3):
		data3.extend([str(i+2*3)*4])
	
	alloc1 = m1.permute_global(pubseed, 9, nbmix, 1)
	sortout1 = m1.sort_global_out(data1, alloc1)
	
	alloc2 = m2.permute_global(pubseed, 9, nbmix, 1)
	sortout2 = m2.sort_global_out(data2, alloc2)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 1)
	sortout3 = m3.sort_global_out(data3, alloc3)

	print "----------------------------------------------------------"


	received1=[sortout1[0], sortout2[0], sortout3[0]]
	received2=[sortout1[1], sortout2[1], sortout3[1]]
	received3=[sortout1[2], sortout2[2], sortout3[2]]

	alloc1 = m1.permute_global(pubseed, 9, nbmix, 1)
	sortin1 = m1.sort_global_in(received1, alloc1)
	aes = Cipher("AES-128-CTR")
	enc = aes.enc(key1, iv1)
	for i in range(len(sortin1)):
		sortin1[i] = enc.update(sortin1[i])
		sortin1[i] += enc.finalize()
	sortin1 = m1.permute(seed1, sortin1, 1)
	
	alloc2 = m2.permute_global(pubseed, 9, nbmix, 1)
	sortin2 = m2.sort_global_in(received2, alloc2)
	aes = Cipher("AES-128-CTR")
	enc = aes.enc(key2, iv2)
	for i in range(len(sortin2)):
		sortin2[i] = enc.update(sortin2[i])
		sortin2[i] += enc.finalize()
	sortin2 = m2.permute(seed2, sortin2, 1)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 1)
	sortin3 = m3.sort_global_in(received3, alloc3)
	aes = Cipher("AES-128-CTR")
	enc = aes.enc(key3, iv3)
	for i in range(len(sortin3)):
		sortin3[i] = enc.update(sortin3[i])
		sortin3[i] += enc.finalize()
	sortin3 = m3.permute(seed3, sortin3, 1)


	alloc1 = m1.permute_global(pubseed2, 9, nbmix, 1)
	sortout1 = m1.sort_global_out(sortin1, alloc1)
	
	alloc2 = m2.permute_global(pubseed2, 9, nbmix, 1)
	sortout2 = m2.sort_global_out(sortin2, alloc2)

	alloc3 = m3.permute_global(pubseed2, 9, nbmix, 1)
	sortout3 = m3.sort_global_out(sortin3, alloc3)

	print "----------------------------------------------------------"

	received1=[sortout1[0], sortout2[0], sortout3[0]]
	received2=[sortout1[1], sortout2[1], sortout3[1]]
	received3=[sortout1[2], sortout2[2], sortout3[2]]

	alloc1 = m1.permute_global(pubseed2, 9, nbmix, 1)
	sortin1 = m1.sort_global_in(received1, alloc1)
	
	alloc2 = m2.permute_global(pubseed2, 9, nbmix, 1)
	sortin2 = m2.sort_global_in(received2, alloc2)

	alloc3 = m3.permute_global(pubseed2, 9, nbmix, 1)
	sortin3 = m3.sort_global_in(received3, alloc3)

	alloc1 = m1.permute_global(pubseed2, 9, nbmix, 0)
	sortout1 = m1.sort_global_out(sortin1, alloc1)

	alloc2 = m2.permute_global(pubseed2, 9, nbmix, 0)
	sortout2 = m2.sort_global_out(sortin2, alloc2)

	alloc3 = m3.permute_global(pubseed2, 9, nbmix, 0)
	sortout3 = m3.sort_global_out(sortin3, alloc3)

	print "----------------------------------------------------------"


	received1=[sortout1[0], sortout2[0], sortout3[0]]
	received2=[sortout1[1], sortout2[1], sortout3[1]]
	received3=[sortout1[2], sortout2[2], sortout3[2]]

	alloc1 = m1.permute_global(pubseed2, 9, nbmix, 0)
	sortin1 = m1.sort_global_in(received1, alloc1)
	sortin1 = m1.permute(seed1, sortin1, 0)
	aes = Cipher("AES-128-CTR")
	enc = aes.enc(key1, iv1)
	for i in range(len(sortin1)):
		sortin1[i] = enc.update(sortin1[i])
		sortin1[i] += enc.finalize()
	
	alloc2 = m2.permute_global(pubseed2, 9, nbmix, 0)
	sortin2 = m2.sort_global_in(received2, alloc2)
	sortin2 = m2.permute(seed2, sortin2, 0)
	aes = Cipher("AES-128-CTR")
	enc = aes.enc(key2, iv2)
	for i in range(len(sortin2)):
		sortin2[i] = enc.update(sortin2[i])
		sortin2[i] += enc.finalize()

	alloc3 = m3.permute_global(pubseed2, 9, nbmix, 0)
	sortin3 = m3.sort_global_in(received3, alloc3)
	sortin3 = m3.permute(seed3, sortin3, 0)
	aes = Cipher("AES-128-CTR")
	enc = aes.enc(key3, iv3)
	for i in range(len(sortin3)):
		sortin3[i] = enc.update(sortin3[i])
		sortin3[i] += enc.finalize()

	alloc1 = m1.permute_global(pubseed, 9, nbmix, 0)
	sortout1 = m1.sort_global_out(sortin1, alloc1)

	alloc2 = m2.permute_global(pubseed, 9, nbmix, 0)
	sortout2 = m2.sort_global_out(sortin2, alloc2)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 0)
	sortout3 = m3.sort_global_out(sortin3, alloc3)

	print "----------------------------------------------------------"

	received1=[sortout1[0], sortout2[0], sortout3[0]]
	received2=[sortout1[1], sortout2[1], sortout3[1]]
	received3=[sortout1[2], sortout2[2], sortout3[2]]

	alloc1 = m1.permute_global(pubseed, 9, nbmix, 0)
	sortin1 = m1.sort_global_in(received1, alloc1)

	alloc2 = m2.permute_global(pubseed, 9, nbmix, 0)
	sortin2 = m2.sort_global_in(received2, alloc2)

	alloc3 = m3.permute_global(pubseed, 9, nbmix, 0)
	sortin3 = m3.sort_global_in(received3, alloc3)


	data = []
	for i in range(9):
		data.append(str(i)*4)
	res = []
	for i in range(len(sortin1)):
		res.append(sortin1[i])
	for i in range(len(sortin2)):
		res.append(sortin2[i])
	for i in range(len(sortin3)):
		res.append(sortin3[i])

	print "res", res
	print "data", data

	assert data == res


