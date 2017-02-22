from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.internet.defer import Deferred
from twisted.internet import reactor
from petlib.cipher import Cipher
import random, sys
from collections import namedtuple
import threading
from petlib import pack
import time 


#http://stackoverflow.com/questions/3275004/how-to-write-a-twisted-server-that-is-also-a-client
Keys = namedtuple('Keys', ['b', 'iv', 'kmac', 'kenc', 'seed'])
Actor = namedtuple('Actor', ['name', 'host', 'port', 'pubk'])

class Mix():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities

	cascade = True

	def __init__(self, name, ip, port, cascade=1, layered=1, rounds=10): 
		#print "Mix: init"

		#Mix initialization
		self.name = name 		# Name of the mix
		self.port = port 		# Port of the mix
		self.ip = ip	 		# IP of the mix
		self.cascade=cascade
		self.layered=layered
		
		#Mix variables
		self.datas = [] # =[[data per mix]]
		self.datalock = threading.Lock()
		self.round = 0

		#Mix instructions
		self.rounds = rounds
		self.secrets = [] #[[old],[new]]
		self.db= [] #=[Actor, range]
		self.list = [] # =[Actors]
		self.listlock = threading.Lock()
		self.index = -1 # mix index in list
		self.sendlock = threading.Lock() # lock for sending

		#Flags for the parallel rebuild phase
		self.dpi = 1
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
			if self.layered: # Cascade Layered
				if self.index != ll-1:
					return [self.list[self.index+1].host],[self.list[self.index+1].port], [self.list[self.index+1].name], 0
				else:
					return [self.db[0].host],[self.db[0].port], ["DB"], self.db[1]
			else: # Cascade Rebuild
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
			ips =[]
			ports = []
			names = []
			for i in range(ll):
				ips.extend([self.list[i].host])
				ports.extend([self.list[i].port])
				names.extend([self.list[i].name])
			if self.layered: # Parallel Layered
				if self.round<self.rounds-1:
					return ips, ports, names, 0
				else:
					return [self.db[0].host],[self.db[0].port], "DB", self.db[1]
			else: # Parallel Rebuild
				if self.epi or self.dpi: # Permutation phases
					return ips, ports, names, 0
				if self.ed: # E/D phase
					idx = self.index+1
					if idx==ll:
						idx=0
					return [self.list[idx].host],[self.list[idx].port], [self.list[idx].name], 0
				if self.end:
					return [self.db[0].host],[self.db[0].port], "DB", self.db[1]

class ServerProto(Protocol):

	def __init__(self):
		#print "SP: init"
		a=0

	def connectionMade(self):
		print "SF: Connection made", self.transport.getPeer()
		self.factory.s_protos.append(self)

	def dataReceived(self, data):
		print "SP: Data received", self.transport.getPeer()
		reactor.callInThread(self.dataParser, data)		

	def dataParser(self,data):
		print "SP: Data parser", pack.decode(data)
		data= pack.decode(data)

		mix = self.factory.mix
		op, vs, content = data # operation, request id, content		

		if "ME" not in op:
			self.transport.loseConnection()

		if "STT" in op: #START - receive instructions
			print "in STT"
			
			mix.dpi=1
			mix.ed=0
			mix.epi=0
			mix.end=0

			mix.db, mix.secrets, mix.list = content

			mix.db=[Actor(mix.db[0][0], mix.db[0][1], mix.db[0][2], mix.db[0][3]), mix.db[1]]
			for i in range(len(mix.list)):
				mix.list[i]=Actor(mix.list[i][0],mix.list[i][1],mix.list[i][2],mix.list[i][3])
				if mix.name in mix.list[i].name:
					mix.index = i

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
			print "in PUT"
			mix.datas = content
			mix.dbcheck = 1
			#print mix.datas
			
		if "MIX" in op and not "ME" in op: #MIX = receive data from mixes
			print "in MIX"
			index = -1
			with mix.datalock:
				if mix.cascade:
					#print "in cascade"
					mix.datas, name =content
				else:
					print "not cascade", self.transport.getPeer().host, self.transport.getPeer().port
					idx = -1
					cntt, name = content
					print "name", name, "len", len(mix.list)
					for i in range(len(mix.list)):
						#print i, mix.list[i].name 
						if mix.list[i].port == self.transport.getPeer().port and mix.list[i].host == self.transport.getPeer().host:
							idx=i
						if mix.list[i].name == name: #needed in local
							idx=i
					#print "after loop", idx, mix.datas
					mix.datas[idx]=cntt
				print "in lock", mix.datas	

		alldata=0
		with mix.datalock:
			for i in range(len(mix.datas)):
				if mix.datas[i] != []:
					alldata += 1


		with mix.datalock:
			print mix.datas
		print "check before thread call", data, mix.cascade, alldata, len(mix.list)
		print mix.round, mix.dpi, mix.ed, mix.epi, mix.end
		if "PUT" in op or ('MIX' in op and ( (mix.cascade) or ((not mix.cascade) and ( alldata==len(mix.list) or (alldata==1 and (mix.ed or mix.end))))) ):
			print "calling thread"
			toprocess = []
			print "locking"
			mix.sendlock.acquire()
			print "sendlock acquired"
			with mix.datalock:
				toprocess = mix.datas
				mix.datas=[]
				if not mix.cascade:
					for i in range(len(mix.list)):
						mix.datas.extend([[]])
			print "data ended", toprocess
			self.computeData(toprocess, vs)
		

	def computeData(self, datas,vs):
		#Encrypt and permute data in thread
		#Return to main thread to send data
		print "SP: Compute Data", datas
		mix = self.factory.mix

		mix.round += 1
		if mix.round == mix.rounds:
			mix.dpi=0
			mix.ed=1
			mix.epi=0
			mix.end=0
		if mix.round == mix.rounds+len(mix.list):
			mix.dpi=0
			mix.ed=0
			mix.epi=1
			mix.end=0
		if mix.round == 2*mix.rounds+len(mix.list):
			mix.dpi=0
			mix.ed=0
			mix.epi=0
			mix.end=1

		dpi=mix.dpi
		ed=mix.ed
		epi=mix.epi
		end=mix.end

		if not mix.cascade:
			if type(datas[0])==list:
				datas = [datas[i][j] for i in range(len(datas)) for j in range(len(datas[i]))]
			else:
				datas= [datas[i] for i in range(len(datas))]
		print "after merge", datas
		for i in range(len(datas)):
				if type(datas[i])==str:
					datas[i]=datas[i]+mix.name+str(mix.round) #TODO
				if type(datas[i])==list:
					for j in range(len(datas[i])):
						datas[i][j]= datas[i][j]+mix.name+str(mix.round) 
		time.sleep(3)
		reactor.callFromThread(self.sendData, datas, vs, dpi, ed, epi, end)

	def sendData(self, datas, vs, dpi, ed, epi, end):
		#Called by function computeData in thread
		#Send data to mixes/db
		print "SP: Send Data", datas
		mix = self.factory.mix
		ips, ports, names, offset = mix.compute_path()
		print ips, ports, offset
		mix.sendlock.release()
		if offset==0:
			c_factories = [] 
			print mix.dpi, mix.ed, mix.epi, mix.end, dpi, ed, epi, end
			if not mix.cascade: # Data allocation
				if mix.layered or (not mix.layered and (dpi or epi)):
					print "splitting"
					datas= mix.split(datas,len(datas)/len(mix.list))
			for i in range(len(ips)):
				tosend = [datas, mix.name]
				if not mix.cascade:
					if mix.layered or (not mix.layered and (dpi or epi)):
						tosend=[datas[i], mix.name] 
				c_factories.extend([ClientFact(self, [ "MIX", vs, tosend ])])	
				c_factories[i].protocol = ClientProto
				if not mix.cascade:
					if names[i]==mix.name :
						print "storing my data"
						with mix.datalock:
							mix.datas[mix.index]=tosend[0]
						self.dataParser(pack.encode(["MIXME", vs, []]))
					else:
						print "sending to "+names[i], tosend			
						reactor.connectTCP(ips[i], ports[i], c_factories[i],5)
				else:
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
			
		print "data written", datas

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
	if len(sys.argv) <4:
		print "ERROR: you have entered "+str(len(sys.argv))+" inputs."
	else:
   
        	mix = Mix(str(sys.argv[1]), str(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
		# name ip port group pub
