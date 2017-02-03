from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.internet.defer import Deferred
from twisted.internet import reactor
from collections import namedtuple
from petlib.bn import Bn
from petlib.ec import EcGroup
from petlib.ec import EcPt
import random, sys
from hashlib import sha512, sha1
Keys = namedtuple('Keys', ['b', 'iv', 'kmac', 'kenc', 'seed'])
Actor = namedtuple('Act', ['name', 'port', 'host', 'pubk'])

class Client():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities
	data = ""
	cascade = True

	def __init__(self, name, port, ip, group, priv, pub, pubs, db_token):
		print "Client: init"
		self.name = name
		self.group = group # G o g o.byte
		self.priv = priv
		self.pub = pub
		self.pubs = [Actor(*pubs[i]) for i in range(len(pubs))] #mixes [[ips, ports & public keys]]
		self.keys = [] #shared secrets with the mixes
		self.db_token = db_token



		if (self.cascade):
			self.data = self.sendCascade()
		else:
			self.data = self.sendParallel()

		for i in range(len(self.data)):
			print self.data[i]


	def run(self):
		for i in range(len(self.pubs)):
			if "M" in self.pubs[i].name:
				c_factory = ClientFact(self, self.data[i])
				c_factory.protocol = ClientProto
				reactor.connectTCP(self.pubs[i].host, self.pubs[i].port, c_factory)
		reactor.run()


	def calculate_all(self, pub, rng, setup):
		G, o, g, o_bytes = setup
		Bs = [] # list of blinding factors
		pubs = [] # list of public values shared between Alice and mix nodes
		shared_secrets = [] # list of shared secret keys between Alice and each mixnode

		rand_nonce = G.order().random()
		init_pub = rand_nonce * self.pub
		prod_bs = Bn(1)
	
		for i in range(rng):
			xysec = (self.priv * rand_nonce * prod_bs) * pub
			shared_secrets.append(xysec)

			# blinding factors
			k = self.KDF(xysec.export())
			b = Bn.from_binary(k.b) % o
			Bs.append(b)
			prod_bs = (b * prod_bs) % o
			pubs.append(prod_bs * init_pub)
		return pubs, shared_secrets

	def get_record(self, index):
		print ""


	def sendCascade(self):
		print ""
		add = []
		meta = []
		db = ""
		for i in range(len(self.pubs)):
			if "M" in self.pubs[i].name:
				add.extend([[self.pubs[i].host,self.pubs[i].port]])
			if "DB" in self.pubs[i].name:
				db=self.pubs[i]
		shared_pub, shared_sec = self.calculate_all(self.pubs[i].pubk[0] ,1, self.group)
		oldkey=1
		if len(self.keys)!=0:
			oldkey=self.keys[0] #?
		meta = [[db.host, db.port, self.db_token, oldkey, shared_pub[0], add]]
		self.keys=shared_pub
		return meta


	def sendParallel(self):
		print ""
		add = []
		meta = []
		db = ""
		for i in range(len(self.pubs)):
			if "M" in self.pubs[i].name:
				add.extend([[self.pubs[i].host, self.pubs[i].port]])
			if "DB" in self.pubs[i].name:
				db=self.pubs[i]
		for i in range(len(self.pubs)):
			if "M" in self.pubs[i].name:
				shared_pub, shared_sec = self.calculate_all(self.pubs[i].pubk[0],1, self.group)
				oldkey=1
				if len(self.keys)>i:
					oldkey=self.keys[i] #?
				temp = [[db.host, db.port, self.db_token, oldkey, shared_pub[0], add]]
				meta.extend(temp)
				print self.keys, len(self.keys),i 
				if (len(self.keys)-i) !=0:
					print len(self.keys)-i
					self.keys[i]=shared_pub[0]
				else:
					self.keys.extend(shared_pub)
		return meta

	def KDF(self, element, idx="A"):
		''' The key derivation function for b, iv, keys and seeds '''
		keys = sha512(element + idx).digest()
		return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64], keys[64:80])

	
class ClientProto(Protocol):
	def __init__(self):
		print "ClientP: init"

	def connectionMade(self):
		print "ClientP: Connection made"
		self.transport.write(self.factory.data)

	def dataReceived(self, data):
        	print "ClientP: Receive:", data

	def connectionLost(self, reason):
        	print "ClientP: Connection lost", reason

class ClientFact(ClientFactory):
	protocol = ClientProto

	def __init__(self, c, meta):
		print "CF: init"
		self.client = c
		self.data =meta

	def clientConnectionFailed(self, connector, reason):
	        print 'CF: Connection failed:', reason.getErrorMessage()
	        self.done.errback(reason)

	def clientConnectionLost(self, connector, reason):
	        print 'CF: Connection lost:', reason.getErrorMessage()
	        self.done.callback(None)




if __name__ == '__main__':
	if len(sys.argv) <6:
		print "ERROR: you have entered "+str(len(sys.argv))+" inputs."
	else:
        	client = Client(str(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9], sys.argv[10])
		# name port ip group priv pub pubs dbip dbport token

