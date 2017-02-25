from twisted.internet.protocol import Protocol, Factory, ClientFactory
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

		self.PERM=0

		#Mix keys
		self.G = EcGroup(713)
		self.o = self.G.order()
		self.g = self.G.generator()
		self.o_bytes = int(math.ceil(math.log(float(int(self.o))) / math.log(256)))	
		#self.s = (self.G, self.o, self.g, self.o_bytes)
		self.prvk= Bn.from_binary(base64.b64decode("/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==")) #mix private key
		self.pubk= self.prvk * self.g #mix public key
		
		#Mix variables
		self.datas = [] # =[[data per mix]]
		self.datalock = threading.Lock() # lock for accessing datas
		self.round = 0 # current round

		#Mix instructions
		self.records= 0 #n, total number of records
		self.rounds = 0 #r, total number of rounds
		self.alloc=[[],[]] #[[old],[new]] record-mix allocation
		self.db= [] #=[Actor, range]
		self.receive = 0 #number of messages received
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
		self.stt = 0
		self.dpi = 0
		self.ed = 0
		self.epi = 0
		self.end = 0

		#Initializing the server
		self.s_factory = ServerFact(self)
		reactor.listenTCP(self.port, self.s_factory)
		reactor.run()

	def split(self, tosplit, k):
		return [tosplit[i:i+k] for i in range(0, len(tosplit), k)]

	def compute_path(self):
		#print "MIX: Compute Path"
		ll = -1
		with self.listlock:
			ll=len(self.list)
		if self.cascade:
			#print "in Cascade"
			#print self.index, self.round
			if self.layered: # Cascade Layered
				print "in Layered"
				if self.index != ll-1:
					return [self.list[self.index+1].host],[self.list[self.index+1].port], [self.list[self.index+1].name], 0
				else:
					return [self.db[0].host],[self.db[0].port], ["DB"], self.db[1]
			else: # Cascade Rebuild
				#print "in Rebuild"
				if self.round==0: # D/Pi phase
					if self.index != ll-1:
						return [self.list[self.index+1].host],[self.list[self.index+1].port], [self.list[self.index+1].name], 0
					else:
						return [self.list[self.index].host],[self.list[self.index].port], [self.list[self.index].name], 0
				else:
					if self.index != 0:
						return [self.list[self.index-1].host],[self.list[self.index-1].port], [self.list[self.index-1].name], 0
					else:
						if self.round==1: # E/D phase
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
				print "in Rebuild"
				if self.stt or self.epi or self.dpi: # Permutation phases
					print "in stt epi dpi", self.stt, self.epi, self.dpi
					return ips, ports, names, 0
				if self.ed: # E/D phase
					idx = self.index+1
					if idx==ll:
						idx=0
					return [self.list[idx].host],[self.list[idx].port], [self.list[idx].name], 0
				if self.end:
					return [self.db[0].host],[self.db[0].port], "DB", self.db[1]



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
		#print "tosend filtered", tosend
		return tosend 

	def sort_global_in(self, data, order):
		#Input: previous public seed, data arrays [[data from mix_1],...[from mix_m]], allocation (permute_global(seed, n, m, inverse)), inverse boolean
		#Output: Data merged and sorted according to previous public seed [rec_{i*n/m},...rec_{(i+1)*n/m-1}]
		#print "MIX: Sort global in", data, order
		order = order[self.index]
		#print order

		perm=[]
		for i in range(len(order)):
			perm.extend([[i,order[i]]])
		#print perm
		perm.sort(key=lambda t:t[1])
		
		indices=[]
		for i in range(len(self.list)):
			indices.extend([[]])

		#print order, self.records, len(self.list)
		for i in range(len(order)):
			indices[order[i] / (self.records/len(self.list))].append(order[i])
		indices = [j for i in indices for j in i]
		#print indices

		if type(data[0])==list:
			data=[data[i][j] for i in range(len(data)) for j in range(len(data[i]))]
		else:
			data= [data[i] for i in range(len(data))]
		
		zipped = zip(indices, data)
		#print zipped
		zipped.sort(key= lambda t: t[0])
		data=[zipped[i][1] for i in range(len(zipped))]
		
		zipped=zip(perm,data)
		zipped.sort(key= lambda t: t[0][0])
		#print zipped

		received = [zipped[i][1] for i in range(len(zipped))]
		#print "MIX: Sort global in",received
		return received  

	def sort_global_out(self, data, order):
		#Input: previous public seed, data array [rec_{i*n/m},...rec_{(i+1)*n/m-1}], allocation (permute_global(seed, n, m, inverse))
		#Output: Data merged and sorted according to previous public seed [[data from mix_1],...[from mix_m]]
		#print "MIX: Sort global out", data, order
		offset = self.index*(self.records/len(self.list))
		rnge = (self.index+1)*(self.records/len(self.list))
		tosend= []
		for i in range(len(self.list)):
			tosend.extend([[]])
			tosend[i].extend([data[order[i][j] - offset] for j in range(len(order[i])) if order[i][j] in range(offset, rnge)])

		#print "MIX: Sort global out",tosend
		return tosend
		
	def split(self, tosplit, k):
		#Input: Data array to split, length of resulting subarrays
		#Output: Arrays of arrays of k elements
		return [tosplit[i:i+k] for i in range(0, len(tosplit), k)]

	def encrypt_ctr(self, key, counter, data):
		#Input: Encryption key, counter, data to encrypt/decrypt
		#Output: Data encrypted under key and counter
		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, counter)
		output = enc.update(data)
		output += enc.finalize()
		return output

	def encrypt_cbc(self, iv, key, datablock):
		#Input: Encryption key, datablock=[IV, [label,record]]
		#Output: Encrypted datablock=[E(IV),E([label,record])]
		IV, data = datablock
		IV0 = self.KDF(iv, IV)
		data = self.aes_cbc(key, IV0, data)
		IV1 = self.KDF(iv, data[0:16])
		IV = self.aes_cb(key,IV1, IV)
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

	def cascade_layered(self, seed, key, inverse, data):
		#Cascade Layered data processing function
		self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_cbc(key, data[i])
		return data

	def cascade_rebuild(self, seed, key, inverse, data):
		#Cascade Rebuild data processing function
		if not inverse:
			self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_ctr(key, i, data[i])
		if inverse:
			self.permute(seed, data, inverse)
		return data

	def parallel_layered(self, seed, key, inverse, data):
		#Parallel Layered data processing function
		data = sort_global( seed, data, inverse)#inverse=0 now
		self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_cbc(key, i, data[i])
		return data

	def parallel_rebuild(self, seed, key, inverse, data):	
		#Parallel Rebuild data processing function
		data = sort_global( seed, data, inverse)
		if not inverse:
			self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_ctr(key, i, data[i])
		if inverse:
			self.permute(seed, data, inverse)
		return data

	def computeFromSharedSecrets(self, element):
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
				rounds+=len(self.list)

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
		#update parallel flags
		ll=-1
		with self.listlock:
			ll=len(self.list)

		self.round += 1

		if not self.cascade and not self.layered and self.round == 1:
			self.stt=0
			self.dpi=1
			#self.ed=0
			#self.epi=0
			#self.end=0

		if not self.layered and ((not self.cascade and self.round == self.rounds) or (self.cascade and self.round ==1)):
			#self.stt=0
			self.dpi=0
			self.ed=1
			#self.epi=0
			#self.end=0

		if not self.layered and (( self.cascade and self.round == 2) or  ( not self.cascade and self.round == self.rounds+len(self.list))):
			#self.stt=0
			#self.dpi=0
			self.ed=0
			self.epi=1
			#self.end=0

		if ( self.cascade and self.round == 3) or ( not self.cascade and self.round == 2*self.rounds+len(self.list)):
			#self.stt=0
			#self.dpi=0
			#self.ed=0
			self.epi=0
			self.end=1



class ServerProto(Protocol):

	def __init__(self):
		print "SP: init"

	def connectionMade(self):
		#print "SF: Connection made", self.transport.getPeer()
		self.factory.s_protos.append(self)

	def dataReceived(self, data):
		#print "SP: Data received", self.transport.getPeer()
		reactor.callInThread(self.dataParser, data)		

	def dataParser(self,data):
		#print "SP: Data parser", pack.decode(data)
		data= pack.decode(data)

		mix = self.factory.mix
		op, vs, content = data # operation, request id, content		

		if "MIX" in op:
			mix.receive += 1
			#print "RECEIVE", mix.receive

		if "ME" not in op:
			self.transport.loseConnection()

		if "STT" in op: #START - receive instructions
			#print "in STT"
			
			mix.stt=1
			mix.dpi=0
			mix.ed=0
			mix.epi=0
			mix.end=0

			if mix.cascade:
				mix.db, mix.elprv, mix.list = content
				mix.rounds=1
			else:
				mix.db, mix.elprv, mix.elpub, mix.records, mix.rounds, mix.list = content


			mix.db=[Actor(mix.db[0][0], mix.db[0][1], mix.db[0][2], mix.db[0][3]), mix.db[1]]
			for i in range(len(mix.list)):
				mix.list[i]=Actor(mix.list[i][0],mix.list[i][1],mix.list[i][2],mix.list[i][3])
				if mix.name in mix.list[i].name:
					mix.index = i

			if not mix.cascade:
				a, b, mix.seedspub[1], mix.sharedspub[1]= mix.computeFromSharedSecrets(mix.elpub[1])
				#print "new pubs", a, b, mix.seedspub[1], mix.sharedspub[1]
				mix.alloc[1]= mix.permute_global(mix.seedspub[1][0],mix.records,len(mix.list),0)
				#print "in stt, mixalloc 1 if par/layered", mix.alloc[1]
			
			#print mix.db, mix.elprv, mix.list, mix.rounds
			mix.ivsprv[1], mix.keysprv[1], mix.seedsprv[1], mix.sharedsprv[1]= mix.computeFromSharedSecrets(mix.elprv[1])
			#print "new prv", mix.ivsprv[1], mix.keysprv[1], mix.seedsprv[1], mix.sharedsprv[1]
			#print mix.ivsprv[1], mix.keysprv[1], mix.seedsprv[1], mix.sharedsprv[1]


			if not mix.layered:
				mix.ivsprv[0], mix.keysprv[0], mix.seedsprv[0], mix.sharedsprv[0]= mix.computeFromSharedSecrets(mix.elprv[0])
				mix.ivsprv[0]=mix.ivsprv[0][::-1]
				mix.keysprv[0]=mix.keysprv[0][::-1]
				mix.seedsprv[0]=mix.seedsprv[0][::-1]
				mix.sharedsprv[0]=mix.sharedsprv[0][::-1]
				#print "old prv", mix.ivsprv[0], mix.keysprv[0], mix.seedsprv[0], mix.sharedsprv[0]
				if not mix.cascade:
					a, b, mix.seedspub[0], mix.sharedspub[0]= mix.computeFromSharedSecrets(mix.elpub[0])
					#print "old pubs",a,b, mix.seedspub[0], mix.sharedspub[0]
					mix.seedspub[0]=mix.seedspub[0][:mix.rounds]
					mix.seedspub[0]=mix.seedspub[0][::-1] #we reverse the list
					print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", len(mix.seedsprv[0]), len(mix.seedspub[0])

					mix.alloc[1]= mix.permute_global(mix.seedspub[0][0],mix.records,len(mix.list),1)
				#print "in stt, mixalloc 0 inversed, if par/rebuilt", mix.alloc[1]



			if mix.index==0 or not mix.cascade:
				range1=0
				range2=len(mix.list)*mix.db[1]
				
				if not mix.cascade:
					range1=mix.index*mix.db[1]
					range2=(mix.index+1)*mix.db[1]
				c_factory = ClientFact(self, ["GET", vs, [range1, range2, ""]])
				c_factory.protocol = ClientProto
				reactor.callFromThread(reactor.connectTCP, mix.db[0].host, mix.db[0].port, c_factory,5)


		if "PUT" in op: #PUT - receive data from database
			#print "in PUT"
			mix.datas = content
			mix.dbcheck = 1
			#print mix.datas
			
		if "MIX" in op and not "ME" in op: #MIX = receive data from mixes
			#print "in MIX"

			index = -1
			with mix.datalock:
				if mix.cascade:
					#print "in cascade"
					mix.datas, name =content
				else:
					#print "not cascade", self.transport.getPeer().host, self.transport.getPeer().port
					idx = -1
					cntt, name = content
					#print "name", name, "len", len(mix.list)
					for i in range(len(mix.list)):
						#print i, mix.list[i].name 
						if mix.list[i].port == self.transport.getPeer().port and mix.list[i].host == self.transport.getPeer().host:
							idx=i
						if mix.list[i].name == name: #needed in local
							idx=i
					#print "after loop", idx, mix.datas
					mix.datas[idx]=cntt
					print "datas received frm", mix.list[idx].name, cntt
				#print "in lock", mix.datas	


		with mix.datalock:
			print mix.datas
		#print "Check if data can be send", data, mix.cascade, mix.layered, mix.receive, len(mix.list)
		print mix.stt, mix.dpi, mix.ed, mix.epi, mix.end
		print mix.round, mix.rounds
		print mix.receive
		if "PUT" in op or ('MIX' in op and ( (mix.cascade) or ((not mix.cascade) and ( mix.receive==len(mix.list) or ((mix.ed)  and ((mix.round==mix.rounds and mix.receive==len(mix.list)) or (mix.round>mix.rounds)) or (mix.epi and mix.round==mix.rounds+len(mix.list)) )))) ):
			print "Data can be sent, Start computing, calling thread", data

			mix.receive = 0
			print "RECEIVE 0"

			toprocess = []
			print "Waiting for sendlock"
			mix.sendlock.acquire()
			print "Sendlock acquired"
			with mix.datalock:
				toprocess = mix.datas
				mix.datas=[]
				if not mix.cascade:
					for i in range(len(mix.list)):
						mix.datas.extend([[]])
			print "Data reinitialization ended, computing data received", toprocess
			self.computeData(toprocess, vs)
		

	def computeData(self, datas,vs):
		#Encrypt and permute data in thread
		#Return to main thread to send data
		#print "SP: Compute Data", datas
		mix = self.factory.mix

		dpi=mix.dpi
		stt=mix.stt
		ed=mix.ed
		epi=mix.epi
		end=mix.end
		rnd=mix.round

		if epi:
			mix.PERM+=1
		if dpi:
			mix.PERM-=1
		print "PERM", mix.PERM, "-------------------------------------------------------------"	

		print stt,dpi,ed,epi,end,rnd
		print "ALLOC", mix.alloc
		#Sort received data thanks to allocation
		if not mix.cascade and (epi or dpi or end): #if parallel and not start nor ed
			print "in first cond"
			datas = mix.sort_global_in(datas, mix.alloc[0])
		else:
			if type(datas[0])==list:
				datas=[datas[i][j] for i in range(len(datas)) for j in range(len(datas[i]))]
			else:
				datas= [datas[i] for i in range(len(datas))]
		print "Sorting when receiving finished", datas
		
		#Encrypt and permute data
		#print mix.seedsprv, rnd
		#if mix.layered or dpi:
		#	datas = mix.permute(mix.seedsprv[1][rnd], datas, 0)
		#if epi:
		#	datas = mix.permute(mix.seedsprv[1][rnd-mix.rounds - len(mix.list)], datas, 0)
		#if ed:
		#	print "no permutation"
		print "data permuted", datas

		for i in range(len(datas)):
				tt= str(rnd)+str(mix.index*(mix.records/len(mix.list))+i)
				if ed:
					tt= str(rnd)
				if type(datas[i])==str:
					datas[i]=datas[i]+mix.name+tt #TODO
				if type(datas[i])==list:
					for j in range(len(datas[i])):
						datas[i][j]= datas[i][j]+mix.name+str(rnd)+str(i)+str(j) 

		#Sort data thanks to allocation
		if not mix.cascade: #if parallel and not ed nor end
			if mix.layered or (not mix.layered and (stt or dpi or epi)):
				datas = mix.sort_global_out(datas, mix.alloc[1])

		print "Sorting before sending finished", datas


		if not mix.cascade and (mix.end or mix.ed):
			if type(datas[0])==list:
				datas = [datas[i][j] for i in range(len(datas)) for j in range(len(datas[i]))]
		#	else:
		#		datas= [datas[i] for i in range(len(datas))]
		print "after merge", datas
		

		time.sleep(3)
		reactor.callFromThread(self.sendData, datas, vs, stt, dpi, ed, epi, end)

	def sendData(self, datas, vs, stt, dpi, ed, epi, end):
		#Called by function computeData in thread
		#Send data to mixes/db
		print "SP: Send Data", datas
		mix = self.factory.mix
		ips, ports, names, offset = mix.compute_path()
		print ips, ports, offset

		#update rounds
		mix.update_flags()

		print mix.stt, mix.dpi, mix.ed, mix.epi, mix.end, mix.round

		#update record allocation
		if not mix.cascade and not mix.ed:
			inverse = 0
			if not mix.layered and mix.dpi:
				inverse=1
				print len(mix.seedspub[0]), mix.round
				mix.alloc=[mix.alloc[1], mix.permute_global(mix.seedspub[0][mix.round],mix.records,len(mix.list),inverse)]
				print "UPDATE OLD SEED", mix.round,"/",len(mix.seedspub[0])
			else:
				rnd = mix.round
				if not mix.layered:
					rnd = rnd - mix.rounds - len(mix.list)
				print rnd, len(mix.seedspub[1])
				mix.alloc=[mix.alloc[1], mix.permute_global(mix.seedspub[1][rnd],mix.records,len(mix.list),inverse)]
				print "UPDATE NEW seed",rnd,"/",len(mix.seedspub[1])
		if mix.ed and mix.round==mix.rounds - len(mix.list)-1: # if last round of ED, we prepare the alloc of the first round of E/Pi
			print "fist ED round"
			mix.alloc[1]= mix.permute_global(mix.seedspub[1][0],mix.records,len(mix.list),0)
			print "UPDATE NEW SEED 0","/",len(mix.seedspub[1])
		print "updated mix alloc", mix.alloc

		print "releasing sendlock"

		mix.sendlock.release()

		if offset==0:
			c_factories = [] 
			print mix.dpi, mix.ed, mix.epi, mix.end, dpi, ed, epi, end
			for i in range(len(ips)):
				tosend = [datas, mix.name]
				if not mix.cascade:
					if mix.layered or (not mix.layered and (stt or dpi or epi)):
						tosend=[datas[i], mix.name] 
				c_factories.extend([ClientFact(self, [ "MIX", vs, tosend ])])	
				c_factories[i].protocol = ClientProto
				if names[i]==mix.name :
					print "storing my data",tosend
					with mix.datalock:
						if not mix.cascade:
							mix.datas[mix.index]=tosend[0]
						else:
							mix.datas=tosend[0]
					self.dataParser(pack.encode(["MIXME", vs, []]))
				else:
					print "sending to "+names[i], tosend			
					reactor.connectTCP(ips[i], ports[i], c_factories[i],5)

			
		else:
			range1=0
			range2=len(mix.list)*mix.db[1]
			if not mix.cascade:
				range1=mix.index*mix.db[1]
				range2=(mix.index+1)*mix.db[1]
			c_factory=ClientFact(self, ["PUT", vs, [range1, range2, datas] ])
			c_factory.protocol = ClientProto
			reactor.connectTCP(mix.db[0].host, mix.db[0].port, c_factory,5)

		print "data sent to mixes/db", datas 

	def connectionLost(self, reason):
	        print "SP: Connection lost", reason
		self.factory.s_protos.remove(self)


class ServerFact(Factory):
	protocol = ServerProto

	def __init__(self, mix):
		print "SF: init"
		self.mix = mix
		self.s_protos = []

class ClientProto(Protocol):

	def __init__(self):
		print "CP: init"
		self.cdata =""

	def connectionMade(self):
		print "--- CP: Connection made", self.factory.data, self.transport.getPeer()
		self.factory.c_protos.append(self)
		self.cdata=self.factory.data
		self.transport.write(pack.encode(self.factory.data))
		print "--- CP: Connection done", self.factory.data, self.transport.getPeer()

	def dataReceived(self, data):
        	print "CP: Receive:", data, self.transport.getPeer()
		self.transport.loseConnection()
		self.cdata =data
		self.factory.s_proto.dataReceived(data)

	def connectionLost(self, reason):
        	print "CP: Connection lost", reason, self.cdata
		self.factory.c_protos.remove(self)


class ClientFact(ClientFactory):
	protocol = ClientProto

	def __init__(self, s_proto, data):
		print "CF: init",data
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
		print "ERROR: you have entered "+str(len(sys.argv))+" inputs."
		print "name ip port prvk cascade layered expected"
	else:
        	mix = Mix(str(sys.argv[1]), str(sys.argv[2]), int(sys.argv[3]), str(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]))
		# name ip port prvk cascade layered
