from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.internet.defer import Deferred
from twisted.internet import reactor
from petlib.cipher import Cipher
import random, sys
from collections import namedtuple
import threading

#http://stackoverflow.com/questions/3275004/how-to-write-a-twisted-server-that-is-also-a-client
Keys = namedtuple('Keys', ['b', 'iv', 'kmac', 'kenc', 'seed'])
Actor = namedtuple('Mix', ['name', 'port', 'host', 'pubk'])

class Mix():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities

	cascade = True

	def __init__(self, name, ip, port): 
		print "Mix: init"
		self.name = name 		# Name of the mix
		self.port = port 		# Port of the mix
		self.ip = ip	 		# IP of the mix
		
		self.datas = []
		self.datalock = threading.lock()

		self.mixlist = []
		self.listlock = threading.lock()

		self.s_factory = ServerFact(self)
		reactor.listenTCP(self.port, self.s_factory)
		reactor.run()

	def permute(self, seed, data, inverse):
		random.seed(seed)
		perm = random.sample(range(len(data)),len(data))
		temp=[]
		if not inverse:
			for i in range(len(perm)):
				temp.extend([data[perm[i]]])
		else:
			zipped = zip(perm, data)
			zipped.sort(key= lambda t: t[0])
			temp = list(zip(*zipped)[1])
		return temp

	def permute_global(self, seed, n, m, index, inverse):
		random.seed(seed)
		tosend=[]
		temp=permute(seed, range(1,n), inverse)	
		tosend = self.split(temp, n/m)			
		for i in range(len(tosend)):
			tosend[i]= [tosend[i][j] for j in range(len(tosend[i])) if tosend[i][j] in range(index*n/m, (index+1)*n/m)]
		return tosend

	def sort_global(self, seed, data, inverse):
		data = [j for i in data for j in i]
		order = self.permute_global(previous_seed, n, m, index, inverse)
		order = [j for i in order for j in i]
		zipped = zip(order, data)
		zipped.sort(key= lambda t: t[0])
		data = list(zip(*zipped)[1])
		return data
		
	def split(self, tosplit, k):
		return [tosplit[i:i+k] for i in range(0, len(tosplit), k)]

	def encrypt_ctr(self, key, counter, data):
		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, counter)
		output = enc.update(data)
		output += enc.finalize()
		return output

	def encrypt_cbc(self, key, datablock):
		IV, data = datablock
		IV0 = 0 #TODO
		data = self.aes_cbc(key, IV0, data)
		IV1 = 1 #TODO
		data = self.aes_cb(key,IV1, IV)
		datablock = [IV, data]
		return datablock

	def aes_cbc(self, key, IV, data):
		aes = Cipher("AES-128-CBC")
		enc = aes.enc(key, IB)
		output = enc.update(data)
		output += enc.finalize()
		return output		

	def KDF(element, idx="A"):
    		keys = sha512(element + idx).digest()
   		return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64])

	def cascade_layered(self, instructions, data):
		if not inverse:
			self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_cbc(key, data[i])
		if inverse:
			self.permute(seed, data, inverse)
		return data

	def cascade_rebuild(self, instructions, data):
		
		if not inverse:
			self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_ctr(key, i, data[i])
		if inverse:
			self.permute(seed, data, inverse)
		return data

	def parallel_layered(self, instructions, data):

		data = sort_global( seed, data, inverse)
		if not inverse:
			self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_cbc(key, i, data[i])
		if inverse:
			self.permute(seed, data, inverse)
		return data

	def parallel_rebuild(self, instructions, data):	

		data = sort_global( seed, data, inverse)
		if not inverse:
			self.permute(seed, data, inverse)
		for i in range(len(data)):
			data[i]=self.encrypt_ctr(key, i, data[i])
		if inverse:
			self.permute(seed, data, inverse)
		return data	

class ServerProto(Protocol):

	def __init__(self):
		print "SP: init"

	def connectionMade(self):
		print "SF: Connection made"
		self.factory.s_protos.append(self)

	def dataReceived(self, data):
		print "SF: Data received", data
		mix = self.factory.mix
		op, vs, content = data
		if "STT" in op:
			ip, port, range1, range2, instt = content
			c_factory = ClientFact(self, ["GET", vs, [range1, range2]])
			c_factory.protocol = ClientProto
			reactor.connectTCP(ip, port, c_factory)

		else if "PUT" in op:
			data = content
			mix.alldata=1
			
		else if "MIX" in op:
			index = -1
			with mix.listlock:
				index = mix.mixlist.ips.index(self.transport.getPeer().host)
			with mix.datalock:
				if mix.datas[index] == "":
					mix.data[index]=content
					mix.alldata+=1

		if "PUT" in op or (cascade and alldata=1) or ((not cascade) and alldata=len(mixlist.ips)):
			datas = mix.process_data() #TODO
			db, ips, ports = mix.compute_path() #TODO
			if not db:
				c_factories = [] 
				for i in range(ips):
					c_factories.extend(ClientFact(self, [ "MIX", vs, datas[i] ]))	
					c_factories[i].protocol = ClientProto
					reactor.connectTCP(ips[i], ports[i], c_factories[i])
			else:
				c_factory=ClientFact(self, ["PUT", vs, mix.range])
				c_factory.protocol = ClientProto
				reactor.connectTCP(mix.db.ip, mix.db.port, c_factory)

		print "data written"

	def connectionLost(self, reason):
	        print "SF: Connection lost", reason

	def returnData(self, data):
		self.transport.write(data+"_fromS2_") #TODO
		self.transport.loseConnection()

	def processData(self, data):
		print "in processData"
		#Parse & Calculate
		#Encrypt
		#Permute

class ServerFact(Factory):
	protocol = ServerProto

	def __init__(self, mix):
		print "SF: init"
		self.mix = mix
		self.s_protos = []

class ClientProto(Protocol):

	def __init__(self):
		print "CP: init"

	def connectionMade(self):
		print "CP: Connection made"
		self.factory.c_proto = self
		self.transport.write(self.factory.data)

	def dataReceived(self, data):
        	print "CP: Receive:", data
		self.factory.s_proto.returnData(data+"_processedC_")
		self.transport.loseConnection()
		self.factory.s_proto.returnData(data)

	def connectionLost(self, reason):
        	print "CP: Connection lost", reason

class ClientFact(ClientFactory):
	protocol = ClientProto

	def __init__(self, s_proto, data):
		print "CF: init"
		self.done = Deferred()
		self.s_proto = s_proto
		self.c_proto = None
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
   
        	mix = Mix(str(sys.argv[1]), str(sys.argv[2]), int(sys.argv[3]))#, sys.argv[4], sys.argv[5])
		# name ip port group pub
