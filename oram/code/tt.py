from collections import namedtuple
from petlib.cipher import Cipher
from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
import petlib.pack
import base64
import math
import random
from hashlib import sha512, sha1
from eg import ECCEG as eg


Keys = namedtuple('Keys', ['b', 'iv', 'kenc', 'seed'])
Mix = namedtuple('Mix', ['name','privk', 'pkb', 'shared', 'sec'])
Client = namedtuple('Client', ['privk', 'pkb','shared'])
mes_len = 10
privs = [Bn.from_binary(base64.b64decode("DCATXyhAkzSiKaTgCirNJqYh40ha6dcXPw3Pqw==")),  Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ==")), Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))]
privkc = Bn.from_binary(base64.b64decode("/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ=="))


class test():

	def __init__(self, nb_mix=3, nb_rounds=3, nb_ms=3):
		self.mix = nb_mix
		self.rounds = 2*nb_rounds
		self.tag = False

		self.mes = []
		for i in range(nb_ms*nb_mix):
			self.mes.extend([petlib.pack.encode(chr(97+i)*mes_len)])

		self.G = EcGroup(713)
		self.o = self.G.order()
		self.g = self.G.generator()
		self.o_bytes = int(math.ceil(math.log(float(int(self.o))) / math.log(256)))
		self.setup = self.G, self.o, self.g, self.o_bytes
		self.group = (self.G, self.g, self.o)

		shared=[]
		for i in range(self.rounds):
			shared.extend([(privkc * self.create_random() ) * (privkc*self.g)])
		self.client=Client(privkc, privkc *self.g, shared)

		self.mixes=[]
		for i in range(nb_mix):
			p = privs[i%len(privs)]
			shared=[]
			for j in range(self.rounds):
				sec = (self.client.privk * self.create_random() ) * (p*self.g)
				shared.extend([sec])
			sec = (self.client.privk * self.create_random() ) * (p*self.g)
			mix = Mix("M"+str(i), p, p*self.g, shared, sec)
			self.mixes.extend([mix])

		self.e=eg(self.group, privkc, (privkc) * self.g)
		self.randoms = []
		for i in range(nb_ms*nb_mix):
			zero = self.e.enc(0) 
			self.randoms.extend([zero])

	def run(self):
		print "init",
		self.print_mes()
		print "Enc"
		self.EncPrm(self.rounds/2)
		print "Enc done", 
		print self.mes
		print "Dec"
		self.DecUnp(self.rounds/2)
		print "Dec done",
		self.print_mes()

	def tag_mes(self):
		text = "Adding tag"
		if self.tag:
			text = "Removing tags"
		print text
		for i in range(len(self.mes)):
			print i,
			tag = i
			temp = self.mes[i]
			if self.tag:
				tag = self.e.dec(temp[0])
				temp = self.mes[i][1]
			for j in range(self.mix):
				b, iv, key, seed = self.KDF(self.mixes[j].sec.export())
				random.seed(seed*tag)
				blind = []
				for m in range(len(temp)):
					blind.extend([random.randint(0,255)])
				temp = ''.join(chr(ord(a) ^ b) for a,b in zip(temp, blind))
				if not self.tag:
					self.mes[i]=[tag, temp]
				else:
					self.mes[i]=temp
			if not self.tag:
				self.mes[i]=[self.e.enc(tag), self.mes[i][1]]

		print "", "end"
		print self.mes
		self.tag= not self.tag				


	def EncPrm(self, rnd):
		for i in range(self.rounds):
			# We encrypt and permute all message locally
			
			if i == rnd:
				self.tag_mes()

			for j in range(self.mix):
				# The mix compute its key/seeds
				b, iv, key, seed = self.KDF(self.mixes[j].shared[i].export())
				# The mix gets its allocated mixes
				temp= self.mes[j* len(self.mes)/self.mix : (j+1)* len(self.mes)/self.mix]
				
				
				# It encrypts them
				for k in range(len(temp)):
					tag = None
					cipher = temp[k]
					if self.tag:
						rand = random.randint(0,len(self.randoms)-1)
						tag = self.e.add(temp[k][0], self.randoms[rand])
						cipher = temp[k][1]

					cipher = self.aes_enc_dec(key, iv, cipher)
					temp[k]=cipher
					if self.tag:
						temp[k] = [tag, cipher]
						
				
				# It shuffles the messages
				random.seed(seed)	
				random.shuffle(temp)
				
				# Before sending them back
				self.mes[j* len(self.mes)/self.mix : (j+1)* len(self.mes)/self.mix]=temp
	
			# in the right order (We permute the messages globally)
			
			b, iv, key, seed = self.KDF(self.client.shared[i].export())
			random.seed(seed)
			random.shuffle(self.mes)
			random.seed(seed)
			temp = (range(len(self.mes)))
			random.shuffle(temp)
			

	def DecUnp(self, rnd):
		for i in list(reversed(range(self.rounds))):
			
			if i == rnd:
				self.tag_mes()

			# We unpermute the message globally
			b, iv, key, seed = self.KDF(self.client.shared[i].export())
			temp_ord = range(len(self.mes))
			random.seed(seed)	
			random.shuffle(temp_ord)
			zip_ = zip(temp_ord, self.mes)
			zip_.sort()
			self.mes = [zip_[l][1] for l in range(len(zip_))]		

			
			for j in range(self.mix):
				b, iv, key, seed = self.KDF(self.mixes[j].shared[i].export())
				# So that the mixes get the messages we need
				temp=self.mes[j* len(self.mes)/self.mix:(j+1)* len(self.mes)/self.mix]
				
				# It shuffles the messages
				random.seed(seed)
				temp_nb = range(len(temp))	
				random.shuffle(temp_nb)
				zip_ = zip(temp_nb, temp)
				zip_.sort()
				temp = [zip_[l][1] for l in range(len(zip_))]
				
				# It decrypts them
				for k in range(len(temp)):
					tag = None
					cipher = temp[k]
					if self.tag:
						rand = random.randint(0,len(self.randoms)-1)
						tag = self.e.add(temp[k][0], self.randoms[rand])
						cipher = temp[k][1]

					cipher = self.aes_enc_dec(key, iv, cipher)
					temp[k]=cipher
					if self.tag:
						temp[k] = [tag, cipher]

				
				# Before sending them back
				self.mes[j* len(self.mes)/self.mix:(j+1)* len(self.mes)/self.mix] = temp
			
			



	def create_random(self):
		return self.o.random()

	def KDF(self, element, idx="A"):
		''' The key derivation function for b, iv, keys and seeds '''
		keys = sha512(element + idx).digest()
		return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64])

	def aes_enc_dec(self, key, iv, input_):
		"""A helper function which implements the AES-128 encryption in counter mode CTR"""
		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, iv)
		output = enc.update(input_)
		output += enc.finalize()
		return output	
				
	def print_mes(self):
		temp = []
		for i in range(len(self.mes)):
			temp.extend([petlib.pack.decode(self.mes[i])])
		print temp


