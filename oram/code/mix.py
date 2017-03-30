from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.application import service, internet
from twisted.internet.defer import Deferred
from twisted.internet import reactor
from petlib.cipher import Cipher
import random, sys
from collections import namedtuple
import threading
from petlib import pack
import time 
import math
import base64

from hashlib import sha512
from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
from petlib.cipher import Cipher


#http://stackoverflow.com/questions/3275004/how-to-write-a-twisted-server-that-is-also-a-client
Keys = namedtuple('Keys', ['b', 'iv', 'kenc', 'seed'])
Actor = namedtuple('Actor', ['name', 'host', 'port', 'pubk'])

class Session():
# Structure to manage eviction

	def __init__(self, sessionid):
		print "Session: init"
		#Mix variables
		self.id = sessionid
		self.cascade = 0
		self.layered = 0
		self.datas = {} # ={round, [mix:[#pack, #packtot, [datas]]] } dictionary of data
		self.datalock = threading.Lock() # lock for accessing datas
		self.round = 0 # current round

		#Mix instructions
		self.records= 0 #n, total number of records
		self.rounds = 0 #r, total number of rounds
		self.alloc=[[],[]] #[[old],[new]] record-mix allocation
		self.db= [] #=[Actor, range]
		self.list = [] # =[Actors]
		self.listlock = threading.Lock() # lock for accessing list
		self.index = -1 # mix index in list
		self.sendlock = threading.Lock() # lock for sending

		self.elpub  =[[],[]] #[[old],[new]] public elements
		self.sharedspub=[[],[]] #[[old],[new]] public  shared secrets
		self.seedspub=[[],[]] #[[old],[new]] public seeds

		self.elprv = [[],[]] #[[old],[new]] private elements
		self.sharedsprv=[[],[]] #[[old],[new]] private shared secrets
		self.keysprv=[[],[]] #[[old],[new]] private encryption keys
		self.seedsprv=[[],[]] #[[old],[new]] private permutation seeds
		self.ivsprv =[[],[]] #[[old],[new]] private iv tokens

		#Flags for the parallel rebuild phase
		self.stt = 1
		self.dpi = 0
		self.ed = 0
		self.epi = 0
		self.end = 0

	def verify_access(self, sender):
		#verify if sender is among the mix list assigned by the client
		print "Session: Verify"

	def initialize_session(self, content):
		print "Session: initialize"

		self.cascade, self.layered, contt = content
			
		if self.cascade:
			self.db, self.elprv, self.list = contt
			self.rounds=1
		else:
			self.db, self.elprv, self.elpub, self.records, self.rounds, self.list = contt

		#Parsing the list of mixes
		self.db=[Actor(self.db[0][0], self.db[0][1], self.db[0][2], self.db[0][3]), self.db[1]]
		for i in range(len(self.list)):
			self.list[i]=Actor(self.list[i][0],self.list[i][1],self.list[i][2],self.list[i][3])
			if self.name in self.list[i].name:
				self.index = i
		print "my index", self.index

		self.ivsprv[1], self.keysprv[1], self.seedsprv[1], self.sharedsprv[1]= self.computeFromSharedSecrets(self.elprv[1]) # we prepare the first alloc

		if not self.cascade:
			a, b, self.seedspub[1], self.sharedspub[1]= self.computeFromSharedSecrets(self.elpub[1])
			self.alloc[1]= self.permute_global(self.seedspub[1][0],self.records,len(self.list),0)

		if not self.layered:
			self.ivsprv[0], self.keysprv[0], self.seedsprv[0], self.sharedsprv[0]= self.computeFromSharedSecrets(self.elprv[0])
			self.ivsprv[0]=self.ivsprv[0][::-1]
			self.keysprv[0]=self.keysprv[0][::-1]
			self.seedsprv[0]=self.seedsprv[0][:self.rounds]#we reverse the list
			self.seedsprv[0]=self.seedsprv[0][::-1]
			self.sharedsprv[0]=self.sharedsprv[0][::-1]
			if not self.cascade:
				a, b, self.seedspub[0], self.sharedspub[0]= self.computeFromSharedSecrets(self.elpub[0])
				self.seedspub[0]=self.seedspub[0][:self.rounds]
				self.seedspub[0]=self.seedspub[0][::-1] #we reverse the list
				self.sharedspub[0]=self.sharedspub[0][:self.rounds]
				self.sharedspub[0]=self.sharedspub[0][::-1]
				self.alloc[1]= self.permute_global(self.seedspub[0][0],self.records,len(self.list),1)# we prepare the first alloc

	def compute_path(self):
		print "Session: Compute Path"
		#print  self.stt, self.dpi, self.ed, self.epi, self.end
		ll = -1
		with self.listlock:
			ll=len(self.list)
		if self.cascade:
			##print "in Cascade"
			##print self.index, self.round
			if self.layered: # Cascade Layered
				#print "in Layered"
				if self.index != ll-1:
					return [self.list[self.index+1].host],[self.list[self.index+1].port], [self.list[self.index+1].name], 0
				else:
					return [self.db[0].host],[self.db[0].port], ["DB"], self.db[1]
			else: # Cascade Rebuild
				##print "in Rebuild"
				if self.dpi or self.stt: # D/Pi phase
					if self.index != ll-1:
						return [self.list[self.index+1].host],[self.list[self.index+1].port], [self.list[self.index+1].name], 0
					else:
						return [self.list[self.index].host],[self.list[self.index].port], [self.list[self.index].name], 0
				else:
					if self.index != 0:
						return [self.list[self.index-1].host],[self.list[self.index-1].port], [self.list[self.index-1].name], 0
					else:
						if self.ed: # E/D phase
							return [self.list[ll-1].host],[self.list[ll-1].port],[self.list[ll-1].name], 0
						else: # E/Pi phase
							return [self.db[0].host],[self.db[0].port], "DB", self.db[1]
		else:
			#print "in Parallel"
			ips =[]
			ports = []
			names = []
			for i in range(ll):
				ips.extend([self.list[i].host])
				ports.extend([self.list[i].port])
				names.extend([self.list[i].name])
			if self.layered: # Parallel Layered
				#print "in Layered"
				if self.round<self.rounds-1:
					return ips, ports, names, 0
				else:
					return [self.db[0].host],[self.db[0].port], "DB", self.db[1]
			else: # Parallel Rebuild
				#print "in Rebuild"
				if self.stt or self.epi or self.dpi: # Permutation phases
					#print "in stt epi dpi", self.stt, self.epi, self.dpi
					return ips, ports, names, 0
				if self.ed: # E/D phase
					#print "in ed"
					if self.round != self.rounds +ll:
						idx = self.index+1
						if idx==ll:
							idx=0
						return [self.list[idx].host],[self.list[idx].port], [self.list[idx].name], 0
					else:
						#print "last round of ed"
						return ips, ports, names, 0
				if self.end:
					#print "in end"
					return [self.db[0].host],[self.db[0].port], "DB", self.db[1]


	def computeFromSharedSecrets(self, element):
		print "MIX: Compute from Shared Secrets"
		shared_secrets = [] # list of shared secret keys between Client and each mixnode
		Bs = [] # list of blinding factors
		IVs=[] # list of elements for IVs
		Ks=[] # list of encryption keys
		Ss=[] # list of permutation seeds
		prod_bs = Bn(1) #blind product
	
		rounds = self.rounds
		if not self.layered:
			if self.cascade:
				rounds+=1
			else:
				rounds+=len(self.list)+1

		for i in range(rounds):
			xysec = (self.prvk * prod_bs) * element #shared secret
			shared_secrets.append(xysec)
	
			# blinding factors
			k = self.KDF(xysec.export())
			b = Bn.from_binary(k.b) % self.o
			Bs.append(b)
			IVs.append(k.iv)
			Ks.append(k.kenc)
			Ss.append(k.seed)
			prod_bs = (b * prod_bs) % self.o

		return IVs, Ks, Ss, shared_secrets

	def update_flags(self):
		#Update Rebuild methods flags
		print "before updating", self.stt, self.dpi, self.ed, self.epi, self.end
		ll=-1
		with self.listlock:
			ll=len(self.list)

		self.round += 1

		if  not self.layered and ((not self.cascade and self.round == 1) or (self.cascade and round==0)):
			self.stt=0 #Start
			self.dpi=1 #Decryption and permutation
			self.ed=0  #Encryption and decryption
			self.epi=0 #Encryption and permutation
			self.end=0 #End

		if not self.layered and ((not self.cascade and self.round == self.rounds) or (self.cascade and self.round ==1)):
			self.stt=0
			self.dpi=0
			self.ed=1
			self.epi=0
			self.end=0

		if not self.layered and (( self.cascade and self.round == 2) or  ( not self.cascade and self.round == self.rounds+len(self.list)+1)):
			self.stt=0
			self.dpi=0
			self.ed=0
			self.epi=1
			self.end=0

		if ( self.cascade and self.round == 2) or ( not self.cascade and self.round == 2*self.rounds+len(self.list)):
			self.stt=0
			self.dpi=0
			self.ed=0
			self.epi=0
			self.end=1
		print "MIX: Update flag", self.round
		print "before updating", self.stt, self.dpi, self.ed, self.epi, self.end




class Mix():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities

	cascade = True

	def __init__(self, name, ip, port, prvk, cascade=1, layered=1): 
		print "Mix: init",name, ip, port, prvk, cascade, layered

		#Mix initialization
		self.name = name 		# Name of the mix
		self.port = port 		# Port of the mix
		self.ip = ip	 		# IP of the mix
		self.cascade=cascade
		self.layered=layered

		#Mix keys
		self.G = EcGroup(713)
		self.o = self.G.order()
		self.g = self.G.generator()
		self.o_bytes = int(math.ceil(math.log(float(int(self.o))) / math.log(256)))	
		#self.s = (self.G, self.o, self.g, self.o_bytes)
		self.prvk= Bn.from_binary(base64.b64decode("/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==")) #mix private key 
		self.pubk= self.prvk * self.g #mix public key
		
		self.sessions = {} # Eviction session
		self.sessionlock = threading.Lock() #lock for accessing any information

	def split(self, tosplit, k):
		return [tosplit[i:i+k] for i in range(0, len(tosplit), k)]

	def permute(self, seed, data, inverse):
		#Input: permutation seed, data array to permute, inverse boolean
		#Output: Permuted data array
		#print "MIX: Permute", seed, data, inverse
		random.seed(seed)
		perm = []
		while len(perm) != len(data):
			tp=random.randint(0, max(1000,len(data))*len(data))
			if tp not in [perm[i][1] for i in range(len(perm))]:
				perm.extend([[len(perm),tp]])

		order = 1
		if inverse:
			#inverse==1, Pi_{seed}^{-1}(data)
			perm.sort(key= lambda t:t[1])
			order = 0

		for i in range(len(data)):
			if type(data)==list:
				perm[i].extend([data[i]])
		perm.sort(key=lambda t:t[order])

		return [perm[i][2] for i in range(len(perm))]

	def permute_global(self, seed, n, m, inverse):
		#Input: next public seed, number of mixes, mix index, inverse boolean (for D/Pi and E/Pi)
		#Output: Data allocation [[to send to mix_1],...[to send to mix_m]]
		#print "MIX: Permute global", seed, n, m, inverse
		#Calculate public perm
		random.seed(seed)
		tosend=[]
		temp=self.permute(seed, range(0,n), inverse)	
		#Allocate records to all mixes
		tosend = self.split(temp, n/m)	
		#Remove all records but the mix's	
		for i in range(len(tosend)):
			tosend[i]= [tosend[i][j] for j in range(len(tosend[i]))]# if tosend[i][j] in range(self.index*n/m, (self.index+1)*n/m)]
		##print "tosend filtered", tosend
		return tosend 

	def sort_global_in(self, data, order, index):
		#Input: previous public seed, data arrays [[data from mix_1],...[from mix_m]], allocation (permute_global(seed, n, m, inverse)), inverse boolean
		#Output: Data merged and sorted according to previous public seed [rec_{i*n/m},...rec_{(i+1)*n/m-1}]
		#print "MIX: Sort global in", data, order
		order = order[index]
		##print order

		perm=[]
		for i in range(len(order)):
			perm.extend([[i,order[i]]])
		##print perm
		perm.sort(key=lambda t:t[1])
		
		indices=[]
		for i in range(len(self.list)):
			indices.extend([[]])

		##print order, self.records, len(self.list)
		for i in range(len(order)):
			indices[order[i] / (self.records/len(self.list))].append(order[i])
		indices = [j for i in indices for j in i]
		##print indices

		#should already be done now
		#if type(data[0])==list:
		#	data=[data[i][j] for i in range(len(data)) for j in range(len(data[i]))]
		#else:
		#	if type(data)==list:
		#		data= [data[i] for i in range(len(data))]
		
		zipped = zip(indices, data)
		##print zipped
		zipped.sort(key= lambda t: t[0])
		data=[zipped[i][1] for i in range(len(zipped))]
		
		zipped=zip(perm,data)
		zipped.sort(key= lambda t: t[0][0])
		##print zipped

		received = [zipped[i][1] for i in range(len(zipped))]
		##print "MIX: Sort global in",received

		return received  

	def sort_global_out(self, data, order, index, nbmix, nbrecords):
		#Input: previous public seed, data array [rec_{i*n/m},...rec_{(i+1)*n/m-1}], allocation (permute_global(seed, n, m, inverse))
		#Output: Data merged and sorted according to previous public seed [[data from mix_1],...[from mix_m]]
		#print "MIX: Sort global out", data, order
		offset = index*(nbrecords/nbmix)
		rnge = (index+1)*(nbrecords/nbmix)
		#print self.index, offset, rnge
		tosend= []
		for i in range(nbmix):
			tosend.extend([[]])
			#print i, order[i]
			for j in range(len(order[i])):
				#print i,j,"is", order[i][j], "in", range(offset,rnge), "?"
				if order[i][j] in range(offset,rnge):
					#print i,j,"true adding", data, order[i][j]-offset, data[order[i][j]-offset]
					tosend[i].extend([data[order[i][j] - offset]])
			##print "sending to",i,tosend[i]

		##print "MIX: Sort global out",tosend
		return tosend
		
	def split(self, tosplit, k):
		#Input: Data array to split, length of resulting subarrays
		#Output: Arrays of arrays of k elements
		return [tosplit[i:i+k] for i in range(0, len(tosplit), k)]

	def encrypt_cbc(self, key, iv, datablock):
		#Input: Encryption key, datablock=[IV, [label,record]]
		#Output: Encrypted datablock=[E(IV),E([label,record])]
		IV, data = datablock
		IV0 = self.KDF(iv, IV).iv
		data = self.aes_cbc(key, IV0, data)
		IV1 = self.KDF(iv, data[0:16]).iv
		IV = self.aes_cbc(key,IV1, IV)
		datablock = [IV, data]
		return datablock

	def aes_cbc(self, key, IV, data):
		#Input: Encryption key, Initialization vector, data to encrypt
		#Output: Encrypted data with IV and key
		aes = Cipher("AES-128-CBC")
		enc = aes.enc(key, IV)
		output = enc.update(data)
		output += enc.finalize()
		return output		

	def KDF(self, element, idx="A"): #Key derivation function
		#Input: Group element, padding
		#Output: Key object composed of blind, IV, encryption key and permutation seed of 16 bytes each
    		keys = sha512(element + idx).digest()
   		return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64])

	def cascade_layered(self, seed, key, iv, inverse, data):
		#Cascade Layered data processing function
		data=self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_cbc(key, iv, data[i])
		return data

	def cascade_rebuild(self, seed, key, iv, inverse, data):
		#Cascade Rebuild data processing function
		#print "MIX: Cascade Rebuild enc/perm"
		if not inverse and not self.ed:
			data=self.permute(seed, data, inverse)

		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, iv)

		for i in range(len(data)):
			data[i] = enc.update(data[i])
			data[i] += enc.finalize()

		if inverse and not self.ed:
			data=self.permute(seed, data, inverse)
		return data

	def parallel_layered(self, seed, key, iv, inverse, data):
		#Parallel Layered data processing function
		data=self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_cbc(key, iv, data[i])
		return data

	def parallel_rebuild(self, seed, key, iv, inverse, data):	
		#Parallel Rebuild data processing function
		if not inverse and not self.ed:
			#print "Par Rebuild enc/perm : permute", seed, data, inverse
			data=self.permute(seed, data, inverse)

		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, iv)

		#for i in range(len(data)):
		#	data[i] = enc.update(data[i])
		#	data[i] += enc.finalize()

		if inverse and not self.ed:
			#print "Par Rebuild enc/perm : permute", seed, data, inverse
			data=self.permute(seed, data, inverse)
		return data

class ServerProto(Protocol):

	def __init__(self):
		print "SP: init"

	def connectionMade(self):
		#Function called when new connection to the server is made
		#print "SF: Connection made", self.transport.getPeer()
		self.factory.s_protos.append(self)

	def dataReceived(self, data):
		#Function called when some data is received from the made connection
		print "SP: Data received", self.transport.getPeer() #, data
		reactor.callInThread(self.dataParser, data)		

	def dataParser(self,data):
		#Function parsing the packets
		#The inter Mix packet format is as follow [Operation asked, id request, packet for #round, [data], mix] #TODO to change to OP, id, mix, name data
		print "SP: Data parser", len(data)#, pack.decode(data)
		
		#Decode packet connection structure
		data = pack.decode(data) 

		#Parse meta data
		name, op, vs, turn, nbpack, nbtot, content = data # operation, request id, content	

		#Stop connection if function not triggered by the server itself
		if "ME" not in op:
			self.transport.loseConnection()	

		#START - receive instructions, initialize the seeds, keys, ivs
		if "STT" in op:
			print "in STT"
			
			with self.factory.mix.sessionlock:
				if vs not in self.factory.mix.sessions.keys():
				#Create new session if not existing one
					session = Session(vs)
					session.initialize(content)
					self.factory.mix.sessions[vs]=session
					
					if session.index==0 or not session.cascade:
						print "going to fetch"
						range1=0
						range2=len(session.list)*session.db[1]
				
						if not session.cascade:
							range1=session.index*session.db[1]
							range2=(session.index+1)*session.db[1]
						print range1, range2, session.db[0]

					c_factory = ClientFact(self, ["GET", vs, [range1, range2, ""]])
					c_factory.protocol = ClientProto
					reactor.callFromThread(reactor.connectTCP, session.db[0].host, session.db[0].port, c_factory,5)

		#Initi some parameters
		datakeys = []
		senderidx = -1
		with self.factory.mix.sessionlock:
			if vs in self.factory.mix.sessions.keys():
				session = self.factory.mix.sessions[vs]
				with session.datalock:
					datakeys = session.datas.keys()
				ll = []
				with session.listlock:
					ll = session.list
				for i in range(len(ll)):
					if ll[i].host == self.transport.getPeer().host and ll[i].name == name:
						senderidx=i


		#PUT - data received from the database
		if "PUT" in op:
			print "in PUT"

			#if first packet from DB, initialize the session/turn data structure
			if turn not in datakeys:
				print "new turn, creating turn"
				datapack = []
				for i in range(packtot):
					datapack.extend([[]])
				datas = [turn, [0, nbtot, datapack]]
				with self.factory.mix.sessionlock:
					with self.factory.mix.sessions[vs].datalock:
						self.factory.mix.sessions[vs].datas[turn] = 	datas	

			#put data in data structure
			with self.factory.mix.sessionlock:
				with self.factory.mix.sessions[vs].datalock:
					if datas[turn][1][2][nbpack] == []: #TODO create structure
						print "new data, adding data"	
						self.factory.mix.sessions[vs].datas[turn][1][2][nbpack] = content
						self.factory.mix.sessions[vs].datas[turn][1][0] += 1
				
			print "finish PUT"
			#if all packet received from DB, wait a few seconds
			if nbpack == nbtot -1:
				print "last pack, sleeping"
				time.sleep(5)	


		#MIX = receive data from mixes except host
		if "MIX" in op: 
			print "in MIX"

			#if new turn, create structure
			if turn not in datakeys:
				print "new turn, creating turn"
				counter = 1
				with self.factory.mix.sessionlock:
					if not self.factory.mix.sessions[vs].cascade:
						with self.factory.mix.sessions[vs].listlock:
							counter = len(mix.sessions[vs].list)
				datas = []
				for i in range(counter):
					datapack = []
					packtot = -1
					if counter == 1 or i == senderidx:
						for i in range(counter):
							datapack.extend([[]])
						packtot = nbtot

					#in the layered ED phase, we do not expect packets from the any node except the previous (hence packtot=0)
					prevsender = self.factory.mix.sessions[vs].index -1
					if self.factory.mix.sessions[vs].index == 0:
						prevsender = len(self.factory.mix.sessions[vs].list)-1
					if not self.factory.mix.sessions[vs].layered and self.factory.mix.sessions[vs].round >= self.factory.mix.sessions[vs].rounds and self.factory.mix.sessions[vs].round < self.factory.mix.sessions[vs].rounds + len(self.factory.mix.sessions[vs].list) and i != prevsender: #tocheck #TODO  
						packtot = 0

					datas.extend([ [turn, [0, packtot, datapack]] ])
				with self.factory.mix.sessionlock:
					with self.factory.mix.sessions[vs].datalock:
						self.factory.mix.sessions[vs].datas[turn] = datas	

			#if data received by myself, update structure and add all data
			if "ME" in op:
				with self.factory.mix.sessionlock:
					index = self.factory.mix.sessions[vs].index
					with self.factory.mix.sessions[vs].datalock:
						if self.factory.mix.sessions[vs].datas[turn][1][index][2] == []: #TODO create structure
							print "new data, adding data"	
							self.factory.mix.sessions[vs].datas[turn][1][index][2] = content
							self.factory.mix.sessions[vs].datas[turn][1][index][1] = 1
							self.factory.mix.sessions[vs].datas[turn][1][index][0] = 1
			#if data from other mix
			else:
				with self.factory.mix.sessionlock:
					with self.factory.mix.sessions[vs].datalock:
						#if parallel
						if not self.factory.mix.sessions[vs].cascade:
							#if it is the first packet received from the mix/turn, we update the expected nb of packets
							if self.factory.mix.sessions[vs].datas[turn][1][senderidx][1] == -1:
								self.factory.mix.sessions[vs].datas[turn][1][senderidx][1] = nbtot
								datapack=[]
								for i in range(nbtot):
									datapack.extend([[]])
								self.factory.mix.sessions[vs].datas[turn][1][senderidx][2]=datapack
							#if packet not received, we store it
							if  self.factory.mix.sessions[vs].datas[turn][1][senderidx][2][nbpack] == []:
								self.factory.mix.sessions[vs].datas[turn][1][senderidx][2][nbpack] = content
								self.factory.mix.sessions[vs].datas[turn][1][senderidx][0] += 1

						#if cascade, the mix/turn is already initialized
						else:
							#if packet not received, we store it
							if  self.factory.mix.sessions[vs].datas[turn][1][2][nbpack] == []:
								self.factory.mix.sessions[vs].datas[turn][1][2][nbpack] = content
								self.factory.mix.sessions[vs].datas[turn][1][0] += 1

		#Check if data can be sent (look if all packets were received)	
		print "prepare if data can be sent"
		received = 0
		expected = 0
		with self.factory.mix.sessionlock:
			with self.factory.mix.sessions[vs].datalock:
				expected = len(self.factory.mix.sessions[vs].datas[turn])
				for i in range(len(self.factory.mix.sessions[vs].datas[turn])):
					if self.factory.mix.sessions[vs].datas[turn][i][0] == self.factory.mix.sessions[vs].datas[turn][i][1]:
						received += 1
			
		if ("PUT" in op or 'MIX' in op) and  received==expected:
			print "Data from turn", turn,"can be sent, Start computing"

			#Erasing data to send from mix.datas
			toprocess = []
			with self.factory.mix.sessionlock:
				with self.factory.mix.sessions[vs].datalock:
					for i in range(len(self.factory.mix.sessions[vs].datas[turn][1][2])):
						toprocess.extend(self.factory.mix.sessions[vs].datas[turn][1][2][i])
					#print "deleting ",min(mix.datas.keys()), mix.datas[min(mix.datas.keys())]
					del self.factory.mix.sessions[vs].datas[turn][1][2]

			#Calling process Data
			self.processData(toprocess, vs)
		

	def processData(self, datas,vs):
		#Sort, encrypt and permute data
		#Return to main thread to send data
		print "SP: Compute Data", datas

		dpi=-1
		stt=-1
		ed=-1
		epi=-1
		end=-1
		rnd=-1
		rnds=-1
		ll=-1
		layered=-1
		cascade=-1
		alloc=[]
		seedsprv=[]
		keysprv=[]
		ivsprv=[]
		index=-1

		with self.factory.mix.sessionlock:
			dpi=self.factory.mix.sessions[vs].dpi
			stt=self.factory.mix.sessions[vs].stt
			ed=self.factory.mix.sessions[vs].ed
			epi=self.factory.mix.sessions[vs].epi
			end=self.factory.mix.sessions[vs].end
			rnd=self.factory.mix.sessions[vs].round
			rnds=self.factory.mix.sessions[vs].rounds
			ll=self.factory.mix.sessions[vs].list
			layered=self.factory.mix.sessions[vs].layered
			cascade=self.factory.mix.sessions[vs].cascade
			alloc = self.factory.mix.sessions[vs].alloc
			seedsprv=self.factory.mix.sessions[vs].seedsprv
			keysprv=self.factory.mix.sessions[vs].keysprv
			ivsprv=self.factory.mix.sessions[vs].ivsprv
			index = self.factory.mix.sessions[vs].index
		#print stt,dpi,ed,epi,end,rnd

		#Sort received data thanks to allocation
		if not cascade and (epi or dpi or end or (ed and rnd==rnds)): #if parallel and not start nor ed
			print "Sort in", alloc[0], datas
			datas = self.factory.mix.sort_global_in(datas, alloc[0],index)
		#print "After Sorting in when receiving finished", datas
		


		#Permute the data (and prepare the relevant parameters)
		offset=rnds
		if not layered:
			if cascade:
				offset+=1
			else:
				offset+=len(ll)+1

		seed = 0 
		key = 0 
		iv = 0 
		inverse = 0
		if cascade:
			if layered:
				print "Cascade Layered Permute"
				seed = seedsprv[1][rnd]
				key = keysprv[1][rnd]
				iv = ivsprv[1][rnd]
				datas=self.factory.mix.cascade_layered(seed, key, iv, inverse, datas)		
			else:
				print "Cascade Rebuild Permute"
				if epi or ed or end:
					seed = seedsprv[1][rnd-offset]
					key = keysprv[1][rnd-offset]
					iv = ivsprv[1][rnd-offset]
				if stt or dpi:
					seed= seedsprv[0][rnd]
					key= keysprv[0][rnd]
					iv=ivsprv[0][rnd]
					inverse = 1
				datas=self.factory.mix.cascade_rebuild(seed, key, iv, inverse, datas)
				if ed:
					key=.keysprv[0][rnd]
					iv=ivsprv[0][rnd]
					datas=self.factory.mix.cascade_rebuild(seed, key, iv,  inverse, datas)
		else:
			if layered:
				print "Parallel Layered Permute"
				seed = seedsprv[1][rnd]
				key = keysprv[1][rnd]
				iv = ivsprv[1][rnd]
				datas=self.factory.mix.parallel_layered(seed, key, iv, inverse, datas)
			else:
				print "Parallel Rebuild Permute"
				if epi or ed or end:
					#print rnd-offset ,mix.seedsprv[1][rnd-offset]
					seed = seedsprv[1][rnd-offset]
					key = keysprv[1][rnd-offset]
					iv = ivsprv[1][rnd-offset]
				if stt or dpi:
					seed= seedsprv[0][rnd]
					key= keysprv[0][rnd]
					iv= ivsprv[0][rnd]
					inverse = 1
				datas=self.factory.mix.parallel_rebuild(seed, key, iv, inverse, datas)
				if ed:
					key= keysprv[0][rnd]
					iv= ivsprv[0][rnd]
					datas=self.factory.mix.parallel_rebuild(seed, key, iv, inverse, datas)

		reactor.callFromThread(self.sendData, datas, vs, stt, dpi, ed, epi, end, rnd, rnds, len(ll))

	def sendData(self, datas, vs, stt, dpi, ed, epi, end, rnd, rnds, ll):
		#Called by function computeData in thread
		#Sort data and send it to mixes/db
		print "SP: Send Data"#, datas
		
		layered=-1
		cascade=-1
		with self.factory.mix.sessionlock:
			layered=self.factory.mix.layered
			cascade=self.factory.mix.cascade

		#Sort data thanks to allocation
		if not cascade: #if parallel and not ed nor end
			if layered or (not layered and (stt or dpi or epi or (ed and rnd==rnds+ll))):
				print "Sort out", datas, mix.alloc[1]
				datas = mix.sort_global_out(datas, mix.alloc[1])

		print "Sorting out before sending finished", datas

		# Merge data array if needed
		if not cascade and (end or (ed and rnd!= rnds+ ll)):
			if rnd != mix.rounds+len(mix.list):
				if type(datas[0])==list:
					datas = [datas[i][j] for i in range(len(datas)) for j in range(len(datas[i]))]
			else:
				if type(data)==list:
					datas=[ [datas[i]] for i in range(len(datas))]

		print "data merged finished if needed"

		#Compute messages path
		ips, ports, names, offset = self.factory.mix.compute_path()
		print "compute path finished", ips, ports, offset

		#update round and flags
		self.factory.mix.update_flags(vs)

		updatedstt=-1
		updateddpi=-1
		updateded=-1
		updatedepi=-1
		updatedend=-1
		updatedrnd=-1
		seedspub=[]
		alloc=[]
		records=-1
		name = self.factory.mix.name
		with self.factory.mix.sessionlock:
			updatedstt= self.factory.mix.sessions[vs].stt
			updateddpi= self.factory.mix.sessions[vs].dpi
			updateded = self.factory.mix.sessions[vs].ed
			updatedepi= self.factory.mix.sessions[vs].dpi
			updatedend= self.factory.mix.sessions[vs].end
			updatedrnd= self.factory.mix.sessions[vs].round
			seedspub =  self.factory.mix.sessions[vs].seedspub
			alloc = self.factory.mix.sessions[vs].alloc
			records= self.factory.mix.sessions[vs].records

		print "update flag finished", updatedstt, updateddpi, updateded, updatedepi, updatedend

		#update record allocation
		print "updating allocs", alloc
		if not cascade and not updateded:
			inverse = 0
			if not layered and updateddpi:
				print "parallel, dpi"
				inverse=1
				alloc=[alloc[1], self.factory.mix.permute_global(seedspub[0][updatedrnd],records,ll),inverse)]
				print alloc, updatedrnd
				##print "UPDATE OLD SEED", mix.round,"/",len(mix.seedspub[0])
			else:
				print "parallel not dpi",rnd
				rndd = rnd
				if not layered:
					rndd = rndd - rnds - ll
				alloc=[alloc[1], self.factory.mix.permute_global(seedspub[1][rndd],records,ll,inverse)]
				##print "UPDATE NEW seed",rnd,"/",len(mix.seedspub[1])
		if updatedepi and updatedrnd==rnds + ll+1: 
			# if rnd=last round of ED (or first EPI round == mix.round), we prepare the alloc of the first round of E/Pi
			print "last round of ed"
			alloc[0]= self.factory.mix.permute_global(seedspub[1][0],records,ll, 0)
			alloc[1]= self.factory.mix.permute_global(seedspub[1][1],records,ll, 0)
		if updateded and updatedrnd == rnds:
			print "first round ed"
			alloc=[alloc[1], self.factory.mix.permute_global(seedspub[1][0],records,ll, 0)]
		with self.factory.mix.sessionlock:
			self.factory.mix.sessions[vs].alloc=alloc
		print "SP: updated allocs", mix.alloc
			
		print "sending data"
		if offset==0:
			#Sending data to mixes
			for i in range(len(ips)):
				#Prepare data
				tosend = datas
				if not cascade:
					if layered or (not layered and (stt or dpi or epi or (ed and rnd==rnds+ll))):
						tosend=datas[i] 

				if names[i] == name :
					#If send data to itself, store data and call dataParser
					reactor.callInThread(self.dataParser, pack.encode([name, "MIXME", vs, updatedrnd, 0, 1, tosend]))
				else:
					#Create clients
					#TODO if record size = s,  len(tosend) / ( create 20kB/s ) clients
					size = sys.getsizeof(tosend[0]) #record size is an invariant
					nbrec = 20000 / size
					nbpack = len(tosend)/nbrec
					c_factories = []
					for j in range(nbpack):
						c_factories.extend([ClientFact(self, [ name, "MIX", vs, updatedrnd, nbpack, nbtot, tosend[j*nbrec:(j+1)*nbrec] ])])	
						c_factories[j].protocol = ClientProto
						reactor.connectTCP(ips[i], ports[i], c_factories[j], 5)

			
		else:
			#If data to be sent to the Database
			#Prepare range to put the data in
			db=[]
			index =-1
			with self.factory.mix.sessionlock:
				db= self.factory.mix.sessions[vs].db
				index = self.factory.mix.sessions[vs].index
			range1=0
			range2=ll*db[1]
			if not cascade:
				range1=index*db[1]
				range2=(index+1)*db[1]
			#Create client and send data
			c_factory=ClientFact(self, ["PUT", vs, [range1, range2, datas] ])
			c_factory.protocol = ClientProto
			reactor.connectTCP(db[0].host, db[0].port, c_factory,5)

		print "data sent to mixes/db"#, datas 

	def connectionLost(self, reason):
	        #print "SP: Connection lost", reason
		self.factory.s_protos.remove(self)


class MixServer(Factory):
	protocol = ServerProto

	def __init__(self, name, ip, port, prvk, cascade=1, layered=1):
		#print "SF: init"
		self.port=port
		self.mix = Mix(name, ip, port, prvk, cascade, layered)
		self.s_protos = []
		#self.run()


	def run(self):
		#Run the MixServer
		#print "Run MixServer"
		#tcp_server = internet.TCPServer(self.port, self.mix)	

		#application = service.Application("Mixnode")
		#tcp_server.setServiceParent(application)
		reactor.listenTCP(self.port, self)
		reactor.run()


class ClientProto(Protocol):

	def __init__(self):
		#print "CP: init"
		self.cdata =""

	def connectionMade(self):
		# Function called when connection made with DB
		# Send GET packet previously made
		print "--- CP: Connection made",  self.transport.getPeer() ,self.factory.data,
		self.factory.c_protos.append(self)
		self.cdata=self.factory.data
		self.transport.write(pack.encode(self.factory.data))
		print "--- CP: Connection done", self.transport.getPeer() #self.factory.data, 

	def dataReceived(self, data):
		# Function called when data received from DB
		# Forward data received to the Server
        	print "CP: Receive:", self.transport.getPeer() #data, 
		self.transport.loseConnection()
		self.cdata =data
		self.factory.s_proto.dataReceived(data)

	def connectionLost(self, reason):
        	print "CP: Connection lost", reason#, self.data
		self.factory.c_protos.remove(self)


class ClientFact(ClientFactory):
	protocol = ClientProto

	def __init__(self, s_proto, data):
		print "CF: init"#,data
		self.done = Deferred()
		self.s_proto = s_proto
		self.c_protos = []
		self.data = data

	def clientConnectionFailed(self, connector, reason):
	        print 'CF: Connection failed:', reason.getErrorMessage()
	        self.done.errback(reason)

	def clientConnectionLost(self, connector, reason):
	        print 'CF: Connection lost:', reason.getErrorMessage()
	        self.done.callback(None)


if __name__ == '__main__':
	if len(sys.argv) <6:
		#print "ERROR: you have entered "+str(len(sys.argv))+" inputs."
		print "name ip port prvk cascade layered expected"
	else:
        	mixnode = MixServer(str(sys.argv[1]), str(sys.argv[2]), int(sys.argv[3]), str(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]))
		mixnode.run()
		# name ip port prvk cascade layered
