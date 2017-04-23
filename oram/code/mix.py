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

	def __init__(self, sessionid, name, setup):
		print "Session: init"

		self.name=name
		self.G, self.o, self.g, self.o_bytes, self.prvk, self.pubk = setup

		#Mix variables
		self.id = sessionid
		self.cascade = 0
		self.layered = 0
		self.datas = {} # ={round, [mix: [#pack, #packtot, [datas]] ] } dictionary of data
		self.datalock = threading.Lock() # lock for accessing datas
		self.round = 0 # current round

		#Mix instructions
		self.records= 0 #n, total number of records
		self.rounds = 0 #r, total number of rounds

		self.alloc=[[],[]] #[[old],[new]] record-mix allocation
		self.alloclock = threading.Lock # lock for accessing alloc

		self.db= [] #=[Actor, range]
		self.list = [] # =[Actors]
		self.listlock = threading.Lock() # lock for accessing list
		self.index = -1 # mix index in list
		self.param = [] # cascade, layered, db, lst, index, rounds, records 

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
		self.flags = [self.stt, self.dpi, self.ed, self.epi, self.end]


class Mix():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities

	cascade = True

	def __init__(self, name, ip, port, prvk, cascade=1, layered=1): 
		print "Mix: init",name, ip, port, prvk, cascade, layered

		#Mix initialization
		self.name = name 		# Name of the mix
		self.port = port 		# Port of the mix
		self.ip = ip	 		# IP of the mix

		#Mix keys
		self.G = EcGroup(713)
		self.o = self.G.order()
		self.g = self.G.generator()
		self.o_bytes = int(math.ceil(math.log(float(int(self.o))) / math.log(256)))	
		self.s = (self.G, self.o, self.g, self.o_bytes)
		self.prvk= Bn.from_binary(base64.b64decode("/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==")) #mix private key 
		self.pubk= self.prvk * self.g #mix public key
		self.setup=(self.G, self.o, self.g, self.o_bytes, self.prvk, self.pubk)
		
		self.sessions = {} # Eviction session
		self.sessionlock = threading.Lock() #lock for accessing any information

	def split(self, tosplit, k):
		return [tosplit[i:i+k] for i in range(0, len(tosplit), k)]

	def verify_access(self, sender):
		#verify if sender is among the mix list assigned by the client
		print "Session: Verify"

	def initialize_session(self, session, content):
		print "Session: initialize"

		session.cascade, session.layered, contt = content
			
		if session.cascade:
			session.db, session.elprv,session.records, session.rounds, session.list = contt
			session.rounds=1
		else:
			session.db, session.elprv, session.elpub, session.records, session.rounds, session.list = contt

		#Parsing the list of mixes
		session.db=[Actor(session.db[0][0], session.db[0][1], session.db[0][2], session.db[0][3]), session.db[1]]
		for i in range(len(session.list)):
			session.list[i]=Actor(session.list[i][0],session.list[i][1],session.list[i][2],session.list[i][3])
			if session.name in session.list[i].name:
				session.index = i

		session.param = [ session.cascade, session.layered, session.db, session.list, session.index, session.rounds, session.records]

		session.ivsprv[1], session.keysprv[1], session.seedsprv[1], session.sharedsprv[1]= self.computeFromSharedSecrets(session.elprv[1], session.param) 
		# we prepare the first alloc

		if not session.cascade:
			#print "not cascade"
			a, b, session.seedspub[1], session.sharedspub[1]= self.computeFromSharedSecrets(session.elpub[1], session.param)
			session.alloc[1]= self.permute_global(session.seedspub[1][0],session.records,len(session.list),0)

		if not session.layered:
			#print "not layered"
			session.ivsprv[0], session.keysprv[0], session.seedsprv[0], session.sharedsprv[0]= self.computeFromSharedSecrets(session.elprv[0], session.param)
			session.ivsprv[0]= session.ivsprv[0][len(session.ivsprv[0])-session.rounds:][::-1] + session.ivsprv[0][:len(session.ivsprv[0])-session.rounds]
			session.keysprv[0]= session.keysprv[0][len(session.keysprv[0])-session.rounds:][::-1]+ session.keysprv[0][:len(session.keysprv[0])-session.rounds]
			session.seedsprv[0]=session.seedsprv[0][:session.rounds]#we reverse the list
			session.seedsprv[0]=session.seedsprv[0][::-1]
			session.sharedsprv[0]=session.sharedsprv[0][::-1]
			if not session.cascade:
				#print "not cascade 2"
				a, b, session.seedspub[0], session.sharedspub[0]= self.computeFromSharedSecrets(session.elpub[0], session.param)
				session.seedspub[0]=session.seedspub[0][:session.rounds]
				session.seedspub[0]=session.seedspub[0][::-1] #we reverse the list
				session.sharedspub[0]=session.sharedspub[0][:session.rounds]
				session.sharedspub[0]=session.sharedspub[0][::-1]
				session.alloc[1]= self.permute_global(session.seedspub[0][0],session.records,len(session.list),1)# we prepare the first alloc
			print "SEEDSPUB", session.seedspub
		print "SEEDSPRV",session.seedsprv
		print "KEYSPRV",session.keysprv
		print "IVSPRV",session.ivsprv
		print "allocs and keys init finished"

	def compute_path(self, param, flags, turn):
		print "Session: Compute Path", flags
		
		cascade, layered, db, lst, index, rounds, records = param
		stt, dpi, ed, epi, end = flags
		ll = len(lst)

		if cascade:
			##print "in Cascade"
			##print index, round
			if layered: # Cascade Layered
				#print "in Layered"
				if index != ll-1:
					return [lst[index+1].host],[lst[index+1].port], [lst[index+1].name], 0
				else:
					return [db[0].host],[db[0].port], ["DB"], db[1]
			else: # Cascade Rebuild
				##print "in Rebuild"
				if dpi or stt: # D/Pi phase
					if index != ll-1:
						return [lst[index+1].host],[lst[index+1].port], [lst[index+1].name], 0
					else:
						return [lst[index].host],[lst[index].port], [lst[index].name], 0
				else:
					if index != 0:
						return [lst[index-1].host],[lst[index-1].port], [lst[index-1].name], 0
					else:
						if ed: # E/D phase
							return [lst[ll-1].host],[lst[ll-1].port],[lst[ll-1].name], 0
						else: # E/Pi phase
							return [db[0].host],[db[0].port], "DB", db[1]
		else:
			#print "in Parallel"
			ips =[]
			ports = []
			names = []
			for i in range(ll):
				ips.extend([lst[i].host])
				ports.extend([lst[i].port])
				names.extend([lst[i].name])
			if layered: # Parallel Layered
				#print "in Layered"
				if round<rounds-1:
					return ips, ports, names, 0
				else:
					return [db[0].host],[db[0].port], "DB", db[1]
			else: # Parallel Rebuild
				#print "in Rebuild"
				if stt or epi or dpi: # Permutation phases
					#print "in stt epi dpi", stt, epi, dpi
					return ips, ports, names, 0
				if ed: # E/D phase
					#print "in ed"
					if turn != rounds +ll:
						idx = index+1
						if idx==ll:
							idx=0
						return [lst[idx].host],[lst[idx].port], [lst[idx].name], 0
					else:
						#print "last round of ed"
						return ips, ports, names, 0
				if end:
					#print "in end"
					return [db[0].host],[db[0].port], "DB", db[1]


	def computeFromSharedSecrets(self, element, param):
		print "MIX: Compute from Shared Secrets"

		G, o, g, o_bytes, prvk, pubk = self.setup

		shared_secrets = [] # list of shared secret keys between Client and each mixnode
		Bs = [] # list of blinding factors
		IVs=[] # list of elements for IVs
		Ks=[] # list of encryption keys
		Ss=[] # list of permutation seeds
		prod_bs = Bn(1) #blind product
	
		cascade, layered, db, lst, index, rounds, records = param

		print "rounds", rounds
		if not layered:
			if cascade:
				rounds+=1
			else:
				rounds+=len(lst)+1

		for i in range(rounds):
			xysec = (self.prvk * prod_bs) * element #shared secret
			shared_secrets.append(xysec)
	
			# blinding factors
			k = self.KDF(xysec.export())
			b = Bn.from_binary(k.b) % o
			Bs.append(b)
			IVs.append(k.iv)
			Ks.append(k.kenc)
			Ss.append(k.seed)
			prod_bs = (b * prod_bs) % o

		return IVs, Ks, Ss, shared_secrets

	def update_flags(self, session):
		#Update Rebuild methods flags
		print "before updating", session.stt, session.dpi, session.ed, session.epi, session.end
		ll=-1
		with session.listlock:
			ll=len(session.list)

		session.round += 1

		if  not session.layered and ((not session.cascade and session.round == 1) or (session.cascade and session.round==0)):
			session.stt=0 #Start
			session.dpi=1 #Decryption and permutation
			session.ed=0  #Encryption and decryption
			session.epi=0 #Encryption and permutation
			session.end=0 #End

		if not session.layered and ((not session.cascade and session.round == session.rounds) or (session.cascade and session.round ==1)):
			session.stt=0
			session.dpi=0
			session.ed=1
			session.epi=0
			session.end=0

		if not session.layered and (( session.cascade and session.round == 2) or  ( not session.cascade and session.round == session.rounds+len(session.list)+1)):
			session.stt=0
			session.dpi=0
			session.ed=0
			session.epi=1
			session.end=0

		if ( session.cascade and session.round == 2) or ( not session.cascade and session.round == 2*session.rounds+len(session.list)):
			session.stt=0
			session.dpi=0
			session.ed=0
			session.epi=0
			session.end=1

		session.flags = [session.stt, session.dpi, session.ed, session.epi, session.end]

		print "MIX: Update flag", session.round
		print "after updating", session.stt, session.dpi, session.ed, session.epi, session.end

	def KDF(self, element, idx="A"): #Key derivation function
		#Input: Group element, padding
		#Output: Key object composed of blind, IV, encryption key and permutation seed of 16 bytes each
    		keys = sha512(element + idx).digest()
   		return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64])


	def permute(self, seed, data, inverse):
		#Input: permutation seed, data array to permute, inverse boolean
		#Output: Permuted data array
		#print "MIX: Permute",   inverse
		random.seed(seed)
		perm = []

		if len(data)<15000:
			while len(perm) != len(data):
				tp=random.randint(0, min(100000000,len(data))*len(data))
				if tp not in perm:
					perm.extend([tp])
		else:
			h=[0]*(min(100000000,len(data)*len(data)))
			t2=time()
		
			while len(perm) != len(data):
				tp=random.randint(0, min(100000000,len(data)*len(data)))
				if h[tp] == 0:
					perm.extend([tp])
					h[tp]=1

		for i in range(len(perm)):
			perm[i]=[i,perm[i]]

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
		#print "MIX: Permute global",  n, m, inverse
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

	def sort_global_in(self, data, order, param):
		#Input: previous public seed, data arrays [[data from mix_1],...[from mix_m]], allocation (permute_global(seed, n, m, inverse)), inverse boolean
		#Output: Data merged and sorted according to previous public seed [rec_{i*n/m},...rec_{(i+1)*n/m-1}]
		#print "MIX: Sort global in", data, order


		cascade, layered, db, lst, index, rounds, records = param
		order = order[index]
		ll = len(lst)
		##print order

		perm=[]
		for i in range(len(order)):
			perm.extend([[i,order[i]]])
		##print perm
		perm.sort(key=lambda t:t[1])
		
		indices=[]
		for i in range(ll):
			indices.extend([[]])

		##print order, self.records, len(self.list)
		for i in range(len(order)):
			indices[order[i] / (records/ll)].append(order[i])
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

	def sort_global_out(self, data, order, param):
		#Input: previous public seed, data array [rec_{i*n/m},...rec_{(i+1)*n/m-1}], allocation (permute_global(seed, n, m, inverse))
		#Output: Data merged and sorted according to previous public seed [[data from mix_1],...[from mix_m]]
		#print "MIX: Sort global out", data, order


		cascade, layered, db, lst, index, rounds, records = param
		ll = len(lst)
		offset = index*(records/ll)
		rnge = (index+1)*(records/ll)
		#print self.index, offset, rnge

		tosend= []
		for i in range(ll):
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

	def cascade_layered(self, seed, key, iv, inverse, data):
		#Cascade Layered data processing function
		data=self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_cbc(key, iv, data[i])
		return data

	def cascade_rebuild(self, seed, key, iv, flags, inverse, data):
		#Cascade Rebuild data processing function
		#print "MIX: Cascade Rebuild enc/perm"
		if not inverse and not flags[2]:
			data=self.permute(seed, data, inverse)

		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, iv)

		#for i in range(len(data)):
		#	data[i] = enc.update(data[i])
		#	data[i] += enc.finalize()

		if inverse and not flags[2]:
			data=self.permute(seed, data, inverse)
		return data

	def parallel_layered(self, seed, key, iv, inverse, data):
		#Parallel Layered data processing function
		data=self.permute(seed, data, inverse)
		#for i in range(len(data)):
		#	data[i]=self.encrypt_cbc(key, iv, data[i])
		return data

	def parallel_rebuild(self, seed, key, iv, flags, inverse, data):	
		#Parallel Rebuild data processing function
		if not inverse and not flags[2]:
			#print "Par Rebuild enc/perm : permute", seed, data, inverse
			data=self.permute(seed, data, inverse)

		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, iv)

		#for i in range(len(data)):
		#	data[i] = enc.update(data[i])
		#	data[i] += enc.finalize()

		if inverse and not flags[2]:
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

		#Decode and Parse meta data
		name, op, vs, turn, option, nbpack, nbtot, content = pack.decode(data) # operation, request id, content	
		print "rec:", name, op, vs, turn, nbpack, nbtot

		#Stop connection if function not triggered by the server itself
		if nbpack >= nbtot-1:
			print "cutting connection", [ self.factory.mix.name, "END", vs, turn, "", nbpack, nbtot, []]
			self.transport.write(pack.encode([ self.factory.mix.name, "END", vs, turn, "", nbpack, nbtot, []]))
			self.transport.loseConnection()	
		else:
			print "asking for next packet", [ self.factory.mix.name, "ACK", vs, turn, "", nbpack, nbtot, []]
			self.transport.write(pack.encode([ self.factory.mix.name, "ACK", vs, turn, "", nbpack, nbtot, []]))

		if "ACK" not in op and "END" not in op:
			reactor.callInThread(self.dataParser, data)		

	def dataParser(self, data):
		#Function parsing the packets
		#The inter Mix packet format is as follow [Operation asked, id request, packet for #round, [data], mix] #TODO to change to OP, id, mix, name data
		print "SP: Data parser", len(data), pack.decode(data)

		session = []
		param = []
		flags = []
		mix = self.factory.mix
		name, op, vs, turn, option, nbpack, nbtot, content = pack.decode(data)

		#START - receive instructions, initialize the seeds, keys, ivs
		if "STT" in op:
			print "in STT"
			self.transport.loseConnection()	
			print "transport closed"

			with mix.sessionlock:
				if vs not in mix.sessions.keys():
				#Create new session if not existing one
					session = Session(vs, mix.name, mix.setup)
					mix.initialize_session(session, content)
					mix.sessions[vs]=session
					print "session created and stored"
					
					if session.index==0 or not session.cascade:
						print "going to fetch"
						range1=0
						range2=len(session.list)*session.db[1]
				
						if not session.cascade:
							range1=session.index*session.db[1]
							range2=(session.index+1)*session.db[1]
						print range1, range2, session.db[0]

						c_factory = ClientFact(self, [mix.name, "GET", vs, 0, [range1, range2]], [""])
						c_factory.protocol = ClientProto
						reactor.callFromThread(reactor.connectTCP, session.db[0].host, session.db[0].port, c_factory,5)

		#Init some parameters
		datakeys = []
		senderidx = -1
		rnd = -1
		print "looking for sender id"
		with mix.sessionlock:
			if vs in mix.sessions.keys():
				session = mix.sessions[vs]
				param = session.param
				flags = session.flags
				rnd = session.round
				with session.datalock:
					datakeys = session.datas.keys()
				lst = []
				with session.listlock:
					lst = session.list
				for i in range(len(lst)):
					if lst[i].name == name:
						#if ll[i].host == self.transport.getPeer().host and ll[i].name == name:
						senderidx=i
		
		cascade, layered, db, lst, index, rnds, records = param
		ll = len(lst)
		print "sender id is ", senderidx


		#PUT - data received from the database
		if "PUT" in op:
			print "in PUT"
			
			#if first packet from DB, initialize the session/turn data structure
			if turn not in datakeys:
				print "new turn, creating turn"
				datapack = []
				for i in range(nbtot):
					datapack.extend([[]])
				datas = [[0, nbtot, datapack]]
				with mix.sessionlock:
					with session.datalock:
						session.datas[turn] = datas	

			#put data in data structure
			print "put in data"
			with mix.sessionlock:
				with session.datalock:
					if not session.datas[turn][0][2][nbpack]:
						print "new data, adding data"
						session.datas[turn][0][2][nbpack] = content
						session.datas[turn][0][0] += 1
				
			print "finish PUT"#, session.datas
			#if all packet received from DB, wait a few seconds
			if nbpack == nbtot -1:
				print "last pack, sleeping"
				time.sleep(5)	


		#MIX = receive data from mixes except host
		if "MIX" in op: 
			print "in MIX"
	 		with mix.sessionlock:
				with session.datalock:
					datakeys = session.datas.keys()

			#if new turn, create structure
			if turn not in datakeys:
				print "new turn, creating turn",turn
				counter = 1
				with mix.sessionlock:
					rnd = session.round
				if not cascade:
					counter = ll
					
				datas = []
				
				for i in range(counter):
					totpack = []
					# we put -1 if we expect an unknown nb of packet, 0 if none expected, the number else
					packtot = -1 

					if cascade or (not cascade and turn in range(rnds+1, rnds+ll+1)):
						packtot = 0

					if counter == 1 or i == senderidx:
						packtot = nbtot
						for j in range(packtot):
							totpack.extend([[]])
					
					datas.extend([ [0, packtot, totpack] ])
		
				with mix.sessionlock:
					with session.datalock:
						if turn not in session.datas:
							session.datas[turn] = datas
							

			print "turn already created"#, session.datas[turn]
			print "adding", len(content), turn, senderidx, nbpack, nbtot
			with mix.sessionlock:
				with session.datalock:
					#if parallel
					if not session.cascade:
						print "in parallel"
						#if it is the first packet received from the mix/turn, we update the expected nb of packets
						if session.datas[turn][senderidx][1] == -1:
							print "first packet received"
							session.datas[turn][senderidx][1] = nbtot
							datapack=[]
							for i in range(nbtot):
								datapack.extend([[]])
							session.datas[turn][senderidx][2]=datapack
						#if packet not received, we store it
						if not session.datas[turn][senderidx][2][nbpack]:
							print "packet not received yet"
							session.datas[turn][senderidx][2][nbpack] = content
							session.datas[turn][senderidx][0] += 1
					#if cascade, the mix/turn is already initialized
					else:
						#if packet not received, we store it
						print session.datas[turn]
						if  not session.datas[turn][0][2][nbpack]:
							session.datas[turn][0][2][nbpack] = content
							session.datas[turn][0][0] += 1


		if session.round not in session.datas.keys():
			print "OUCH", turn, session.round
			return

		#Check if data can be sent (look if all packets were received)	
		print "prepare if data can be sent", session.round
		received = 0
		expected = 0
		with mix.sessionlock:
			with session.datalock:
				#if there is data
				#print session.datas, session.datas[turn]
				#print bool(session.datas), bool(session.datas[turn])
				if session.datas and session.datas[session.round]:
					datas = session.datas[session.round]
					expected = len(datas)
					for i in range(len(datas)):
						#print i, datas[i]
						if datas[i][0] == datas[i][1]:
							received += 1
		
		print op, expected, received
		print flags, rnd,"/", rnds
		#print session.datas
		if ("PUT" in op or 'MIX' in op) and expected!=0 and received==expected:
			print "Data from turn", turn,"can be sent, Start computing"
			print session.datas[rnd]
			#Erasing data to send from mix.datas
			toprocess = []
			with mix.sessionlock:
				with session.datalock:
					for i in range(len(session.datas[rnd])):
						datas = []
						#print i, session.datas[session.round][i]
						for j in range( len( session.datas[rnd][i][2])):
							datas.extend(session.datas[rnd][i][2][j])
						toprocess.extend(datas)
					#print "deleting ",min(mix.datas.keys()), mix.datas[min(mix.datas.keys())]
					print "DELETING",vs,rnd #, session.datas[session.round]
					del session.datas[rnd]

			#Calling process Data
			self.processData(toprocess, vs)
		

	def processData(self, datas, vs):
		#Sort, encrypt and permute data
		#Return to main thread to send data
		print "SP: Compute Data"#, datas
		
		session = []
		mix = self.factory.mix
		param = []
		flags = []
		alloc=[]
		seedsprv=[]
		keysprv=[]
		ivsprv=[]
		rnd=-1
		with mix.sessionlock:
			session = mix.sessions[vs]
			param = session.param
			flags = session.flags
			alloc = session.alloc 
			seedsprv = session.seedsprv
			keysprv = session.keysprv
			ivsprv = session.ivsprv
			rnd = session.round

		cascade, layered, db, lst, index, rnds, records = param
		stt, dpi, ed, epi, end = flags
		ll = len(lst)
		#print stt,dpi,ed,epi,end,rnd

		#Sort received data thanks to allocation
		if not cascade and (epi or dpi or end or (ed and rnd==rnds)): #if parallel and not start nor ed
			print "Sort in", alloc[0], datas
			datas = mix.sort_global_in(datas, alloc[0], param)
		print "After Sorting in when receiving finished", datas
		

		#Permute the data (and prepare the relevant parameters)
		offset=1
		if not layered:
			if not cascade:
				offset+=ll

		seed = 0 
		key = 0 
		iv = 0 
		inverse = 0
		if layered:
			print "Layered Permute"
			seed = seedsprv[1][rnd]
			key = keysprv[1][rnd]
			iv = ivsprv[1][rnd]
			print " --------------------------------------- 1" , rnd, seed
			if cascade:
				datas=mix.cascade_layered(seed, key, iv, inverse, datas)		
			else:
				datas=mix.parallel_layered(seed, key, iv, inverse, datas)
		else:
			print "Rebuild Permute"
			if epi or end:
				print "epiend 1", rnd-rnds-offset
				seed = seedsprv[1][rnd-rnds-offset]
				key = keysprv[1][rnd-rnds]
				iv = ivsprv[1][rnd-rnds]
				print " --------------------------------------- 1" , rnd-rnds
				print " -----------------------------------seed 1" , rnd-rnds-offset
			if stt or dpi:
				print "sttdpi0", rnd
				seed= seedsprv[0][rnd]
				key= keysprv[0][rnd]
				iv=ivsprv[0][rnd]
				inverse = 1
				print " --------------------------------------- 0" , rnd
			if not ed:
				print "not ed"
				if cascade:
					datas=mix.cascade_rebuild(seed, key, iv, flags, inverse, datas)
				else:
					datas=mix.parallel_rebuild(seed, key, iv, flags, inverse, datas)
			else:
				print "ed"
				key=keysprv[0][rnd]
				iv=ivsprv[0][rnd]
				print " --------------------------------------- 0" , rnd
				if cascade:
					datas=mix.cascade_rebuild(seed, key, iv, flags, inverse, datas)
				else:
					datas=mix.parallel_rebuild(seed, key, iv, flags, inverse, datas)
				key=keysprv[1][rnd-rnds]
				iv=ivsprv[1][rnd-rnds]
				print " --------------------------------------- 1" , rnd-rnds
				if cascade:
					datas=mix.cascade_rebuild(seed, key, iv, flags, inverse, datas)
				else:
					datas=mix.parallel_rebuild(seed, key, iv, flags, inverse, datas)
		print "After permuting", datas


		#Sort data thanks to allocation
		if not cascade and (stt or dpi or epi or (ed and rnd==rnds+ll)):
			print "Sort out", datas, alloc[1]
			datas = mix.sort_global_out(datas, alloc[1], param)
		print "Sorting out before sending finished", datas

		# Merge data array if needed
		if not cascade and (end or (ed and rnd!= rnds+ ll)):
			if rnd != rnds+ll:
				if type(datas[0])==list:
					datas = [datas[i][j] for i in range(len(datas)) for j in range(len(datas[i]))]
			else:
				if type(data)==list:
					datas=[ [datas[i]] for i in range(len(datas))]

		print "data merged finished if needed",datas

		#Compute messages path
		ips = []
		ports = []
		names = []
		offset = -1
		with mix.sessionlock:
			ips, ports, names, offset = mix.compute_path(param, flags, rnd)
		path = [ips, ports, names, offset]
		print "Compute path finished", ips, ports, offset


		reactor.callFromThread(self.sendData, datas, vs, flags, rnd, path)

	def sendData(self, datas, vs, flags, rnd, path):
		#Called by function computeData in thread
		#Sort data and send it to mixes/db
		print "SP: Send Data", rnd#, datas
		
		session = []
		param = []
		upflags = []
		seedspub=[]
		alloc=[]
		updatedrnd = -1
		mix = self.factory.mix
		with mix.sessionlock:
			session = mix.sessions[vs]
			param = session.param
			mix.update_flags(session)
			upflags = session.flags
			updatedrnd = session.round
			seedspub =  session.seedspub
			alloc = session.alloc

		stt, dpi, ed, epi, end = flags
		ips, ports, names, offset = path
		cascade, layered, db, lst, index, rnds, records = param
		updatedstt, updateddpi, updateded, updatedepi, updatedend= upflags
		ll=len(lst)

		print "Update flag finished", updatedstt, updateddpi, updateded, updatedepi, updatedend


		#update record allocation
		print "Updating allocs", updatedrnd, upflags, flags#, alloc
		if not cascade:
			if not updateded:
				inverse = 0
				if not layered and updateddpi:
					print "parallel, dpi"
					inverse=1
					alloc=[alloc[1], mix.permute_global(seedspub[0][updatedrnd],records,ll,inverse)]
					print " 0", updatedrnd, "-----------------------------------------"
					print alloc, updatedrnd
					##print "UPDATE OLD SEED", mix.round,"/",len(mix.seedspub[0])
				else:
					print "parallel not dpi",rnd
					rndd = rnd
					if not layered:
						rndd = rndd - rnds - ll +1
					alloc=[alloc[1], mix.permute_global(seedspub[1][rndd],records,ll,inverse)]
					print " 1", rndd, "-----------------------------------------"
					##print "UPDATE NEW seed",rnd,"/",len(mix.seedspub[1])
			if updatedepi and updatedrnd==rnds + ll+1: 
				# if rnd=last round of ED (or first EPI round == mix.round), we prepare the alloc of the first round of E/Pi
				print "last round of ed"
				alloc[0]= mix.permute_global(seedspub[1][0],records,ll, 0)
				alloc[1]= mix.permute_global(seedspub[1][1],records,ll, 0)
				print " 10-11", "-----------------------------------------"
			if updateded and updatedrnd == rnds:
				print "first round ed"
				alloc=[alloc[1], mix.permute_global(seedspub[1][0],records,ll, 0)]
				print " 1", 0, "-----------------------------------------"
			with mix.sessionlock:
				session.alloc=alloc

		print "SP: allocs updated", rnd
		turn = rnd
		if not cascade or (cascade and ((rnd==0 and index == len(lst)-1) or (rnd==1 and index==0))):
			turn = updatedrnd
		print "Sending data"
		if offset==0:
			#Sending data to mixes
			c_factories = []
			for i in range(len(ips)):
				#Prepare data
				tosend = datas
				if not cascade:
					if layered or (not layered and (stt or dpi or epi or (ed and rnd==rnds+ll))):
						tosend=datas[i] 

				if names[i] == mix.name:
					#If send data to itself, store data and call dataParser
					reactor.callInThread(self.dataParser, pack.encode([mix.name, "MIXME", vs, turn, "", 0, 1, tosend]))
				else:
					#Create clients				
					c_factories.extend([ClientFact(self, [ mix.name, "MIX", vs, turn, []], tosend)])	
					c_factories[len(c_factories)-1].protocol = ClientProto
					reactor.connectTCP(ips[i], ports[i], c_factories[len(c_factories)-1], 5)
		else:
			#If data to be sent to the Database
			#Prepare range to put the data in
			db=[]
			index =-1
			with mix.sessionlock:
				db= session.db
				index = session.index
			range1=0
			range2=ll*db[1]
			if not cascade:
				range1=index*db[1]
				range2=(index+1)*db[1]
			#Create client and send data
			c_factory=ClientFact(self, [mix.name, "PUT", vs, turn, [range1, range2]], datas)
			c_factory.protocol = ClientProto
			reactor.connectTCP(db[0].host, db[0].port, c_factory, 5)
			with mix.sessionlock:
				print "DELETING END", session
				del session


		print "Data sent to mixes/db"#, datas 

			

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
		# Send GET packet previously made

		self.factory.c_protos.append(self)
		self.cdata=self.factory.header+[self.factory.counter, self.factory.nbpack]+ [self.factory.data[:self.factory.nbrec]]
		print "CP: CM sending...", self.factory.counter, self.factory.nbpack
		
		if "GET" in self.factory.op:
			self.factory.counter=0
		self.transport.write(pack.encode(self.cdata))

	def dataReceived(self, data):
		# Function called when data received from DB
		# Forward data received to the Server
        	print "CP: Receive:", self.transport.getPeer(), self.factory.header #data,
		self.factory.counter+=1

		name, op, vs, turn, option, turn, tot, content = pack.decode(data)

		if "PUT" in op:
			if turn == 0:
				self.factory.nbpack = int(tot)
			opsend = "END"
			if self.factory.counter != self.factory.nbpack:
				opsend="ACK"
			self.cdata=[ self.factory.name, opsend, self.factory.vs, self.factory.turn,  [self.factory.range1, self.factory.range2], self.factory.counter, self.factory.nbpack, ""]

		else :
			if self.factory.counter != self.factory.nbpack:
				if "PUT" in self.factory.header:
					self.factory.header[4][0] +=  self.factory.nbrec
				self.cdata = self.factory.header+[self.factory.counter, self.factory.nbpack]+[self.factory.data[self.factory.counter*self.factory.nbrec : min(len(self.factory.data),(self.factory.counter+1)*self.factory.nbrec) ]]


		if "END" not in op:
			print "CP: R sending data"#, self.cdata
			self.transport.write(pack.encode(self.cdata))
		else:
			self.transport.loseConnection()

		if "ACK" not in op and "END" not in op:
			self.factory.s_proto.dataParser(data)


	def connectionLost(self, reason):
		self.factory.c_protos.remove(self)


class ClientFact(ClientFactory):
	protocol = ClientProto

	def __init__(self, s_proto, header, data):
		print "CF: init",data
		self.done = Deferred()
		self.s_proto = s_proto
		self.c_protos = []
		self.header = header
		self.name, self.op, self.vs, self.turn, self.option = self.header
		self.range1=-1
		self.range2=-1
		if "GET" in self.op:
			self.range1, self.range2 = self.option
		self.data = data
		self.size = 1
		if "GET" not in self.op and self.data:
			self.size = sys.getsizeof(self.data[0]) #record size is an invariant
		self.nbrec = int(200000.0 / self.size)
		self.nbpack = int(max(1, math.ceil(len(self.data)/float(self.nbrec))))

		self.counter=0

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
