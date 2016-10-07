from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.internet.defer import Deferred
from twisted.internet import reactor
import random, sys


class DB():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities
	data = ""
	session = []

	def __init__(self, name, port, ip, group, pub):
		print "Mix: init"
		self.name = name
		self.port = port
		self.ip = ip
		self.group = group # G o g o.byte
		self.pub = pub #mixes public keys
		self.keys = [] #shared secrets with the mixes
		pdata = data

		c_factory = DBFact(self, pdata)
		c_factory.protocol = ClientProto

		reactor.connectTCP("127.0.0.1", int(self.factory.mix.pub), c_factory)

	def verify_sessionkeys( session ):

	
class DBProto(Protocol):
	def __init__(self):
		print "ClientP: init"

	def connectionMade(self):
		print "ClientP: Connection made"
		self.transport.write(self.factory.data)

	def dataReceived(self, data):
        	print "ClientP: Receive:", data
		if get...

		if put...

	def connectionLost(self, reason):
        	print "ClientP: Connection lost", reason

class DBFact(ClientFactory):
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
   
        	db = DB(str(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
		# name port ip group pub

