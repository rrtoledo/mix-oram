from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.internet.defer import Deferred
from twisted.internet import reactor
import random, sys


class Client():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities
	data = ""
	cascade = True

	def __init__(self, name, port, ip, group, pub):
		print "Mix: init"
		self.name = name
		self.port = port
		self.ip = ip
		self.group = group # G o g o.byte
		self.pub = pub #mixes public keys
		self.keys = [] #shared secrets with the mixes
		pdata = data

		c_factory = ClientFact(self, pdata)
		c_factory.protocol = ClientProto

		if (cascade):
			pdata = sendCascade(data)
		else:
			pdata = sendParallel(data)
		

		reactor.connectTCP("127.0.0.1", int(self.factory.mix.pub), c_factory)

	def calculate_all():
		G, o, g, o_bytes = setup
		Bs = [] # list of blinding factors
		pubs = [] # list of public values shared between Alice and mix nodes
		shared_secrets = [] # list of shared secret keys between Alice and each mixnode

		rand_nonce = G.order().random()
		init_pub = rand_nonce * sender.pubk
		pubs = [init_pub] # pubs = [sedner.pub]
		prod_bs = Bn(1)
	
		for i, node in enumerate(path):
			xysec = (sender.privk * rand_nonce * prod_bs) * node.pubk
			shared_secrets.append(xysec)

			# blinding factors
			k = KDF(xysec.export())
			b = Bn.from_binary(k.b) % o
			Bs.append(b)
			prod_bs = (b * prod_bs) % o
			pubs.append(prod_bs * init_pub)
		return Bs, pubs, shared_secrets

	def get_record(index):

	def sendCascade():
		

	def sendParallel():
		

	
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

	def __init__(self, s_proto, data):
		print "CF: init"
		self.data = data

	def clientConnectionFailed(self, connector, reason):
	        print 'CF: Connection failed:', reason.getErrorMessage()
	        self.done.errback(reason)

	def clientConnectionLost(self, connector, reason):
	        print 'CF: Connection lost:', reason.getErrorMessage()
	        self.done.callback(None)




if __name__ == '__main__':
	if len(sys.argv) <6:
		print "ERROR: you have entered "+len(sys.argv)+" inputs."
	else:
   
        	client = Client(str(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
		# name port ip group pub

