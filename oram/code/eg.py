
## An implementation of an additivelly homomorphic 
## ECC El-Gamal scheme, used in Privex.


from time import time
from petlib.ec import EcGroup
import pytest

class ECCEG():

	def __init__(self, group, prv, pub):
		self.group = group # self.params_gen(nid)
		self.table = self.make_table()
		#keys = self.key_gen()
		self.pub=pub
		self.priv=prv

	def params_gen(self, nid):
		"""Generates the AHEG for an EC group nid"""
		G = EcGroup(nid)
		g = G.generator()
		o = G.order()
		return (G, g, o)

	def key_gen(self):
		"""Generates a fresh key pair"""
		_, g, o = self.group
		priv = o.random()
		pub = priv * g
		return (pub, priv)

	def enc(self, counter):
		"""Encrypts the values of a small counter"""
		assert -2**8 < counter < 2**8
		
		G, g, o = self.group

		k = o.random()
		a = k * g
		b = k * self.pub + counter * g
		return (a, b)

	def enc_side(self, counter):
		"""Encrypts the values of a small counter"""
		assert -2**8 < counter < 2**8
		G, g, o = self.group
		k = o.random()
		a = k * g
		b = k * self.pub + counter * g
		return (a, b, k)


	def add(self, c1, c2):
		"""Add two encrypted counters"""
		a1, b1 = c1
		a2, b2 = c2
		return (a1 + a2, b1 + b2)


	def mul(self, c1, val):
		"""Multiplies an encrypted counter by a public value"""
		a1, b1 = c1
		return (val*a1, val*b1)

	def randomize(self, c1):
		"""Rerandomize an encrypted counter"""
		zero = self.enc(0)
		return self.add(c1, zero)

	def randomize_(self, c1):
		"""Rerandomize an encrypted counter"""
		zero = self.enc(0)
		tic = time()
		temp = self.add(c1, zero)
		toc = time()
		return [temp, toc-tic]

	def make_table(self):
		"""Make a decryption table"""
		_, g, o = self.group
		table = {}
		for i in range(-1000, 1000):
				table[i * g] = i
		return table

	def dec(self, c1):
		"""Decrypt an encrypted counter"""
		_, g, o = self.group
		a, b = c1
		plain = b + (-self.priv * a)
		return self.table[plain] 

	def test(self):

		t = time()
		params = self.params_gen(713)
		t1 = time()
		print " param gen "+ str(t1-t)
		t = time()
		(pub, priv) = self.key_gen()
		t1 = time()
		print " key gen "+str(t1-t)
		t = time()
		table = self.make_table()
		t1 = time()
		print " table gen "+str(t1-t)
		# Check encryption and decryption
		t = time()
		one = self.enc(1)
		t1 = time()
		print " enc "+str(t1-t)
		t = time()
		onee = self.dec(one)
		t1 = time()
		print " dec "+str(t1-t)
		assert self.dec(one) == 1

		# Check addition
		t = time()
		tmp = self.add(one, one)
		t1 = time()
		print " add "+str(t1-t)
		t = time()
		two = self.randomize(tmp)
		t1 = time()
		print " add rd "+str(t1-t)
		assert self.dec(two) == 2

		# Check multiplication
		t = time()
		tmp1 = self.mul(two, 2)
		t1 = time()
		print " mult "+str(t1-t)
		t = time()
		four = self.randomize(tmp1)
		t1 = time()
		print " mult rand "+str(t1-t)
		assert self.dec( four) == 4
