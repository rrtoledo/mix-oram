from __future__ import print_function
from collections import namedtuple
from twisted.internet import reactor, protocol
from twisted.internet.defer import Deferred
from os import urandom
from petlib import pack
import sys
import base64
import math

from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn


Actor = namedtuple('Actor', ['name', 'host', 'port', 'pubk'])
# a client protocol

class Client(protocol.Protocol):

	def __init__(self):
		print("CP: init")

	def connectionMade(self):
		print("CP: Connection Made",self.transport.getPeer())
		self.factory.c_proto=self
		self.transport.write(self.factory.data)

	def dataReceived(self, data):
		print("Server said:", self.transport.getPeer()) # data
		self.transport.loseConnection()

	def connectionLost(self, reason):
		print("connection lost")
		reactor.stop()

class clientFactory(protocol.ClientFactory):
	protocol = Client

	def __init__(self,ip,port):#, arch, enc, el1, el2, el3, el4, ports):
		print("CF: init")
		self.done = Deferred()
		self.c_proto = None
		
		self.ips=ip # ['34.251.168.214','34.249.66.110','34.250.248.33']
		self.ports = port#[8001,8002,8003]
	
		self.G = EcGroup(713)
		self.o = self.G.order()
		self.g = self.G.generator()
		self.o_bytes = int(math.ceil(math.log(float(int(self.o))) / math.log(256)))
		#self.data = ["STT", int(urandom(2).encode('hex'),16), [ Actor("DB", "127.0.0.1", 8000, ""), 3]]
#	if arch:
#	if enc:
#		self.data[2].extend([["", Bn.from_binary(base64.b64decode(el2))]])
#		
#	else:
#		self.data[2].extend([[Bn.from_binary(base64.b64decode(el2)), Bn.from_binary(base64.b64decode(el2))]])
#	else:
#	if enc:
#		self.data[2].extend([["", Bn.from_binary(base64.b64decode(el2))],[["", Bn.from_binary(base64.b64decode(el4))]]])
#	else:
#		self.data[2].extend([ [Bn.from_binary(base64.b64decode(el1)), Bn.from_binary(base64.b64decode(el2))], [Bn.from_binary(base64.b64decode(el3)), Bn.from_binary(base64.b64decode(el4))]])

#	actors=[]
#	for i in range(len(ports)):
#		actors.extend([Actor("M"+str(i), "127.0.0.1", 8001+i, "")])
#	self.data[2].extend([[actors]])

#def test(self):

#self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], ["", Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ]) # cascade layered


#self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], [Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g, Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ]) #cascade rebuild


	#self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], ["", Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], ["", Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g], 9, 2, [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ]) #parallel layered

		self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "34.251.189.234", 8000, ""), 3], [Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g, Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], [Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g, Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g], 9, 2,  [Actor("M1", "34.251.168.214",8001, ""), Actor("M2", "34.249.66.110",8002, ""), Actor("M3", "34.250.248.33", 8003, "")]] ]) #parallel rebuild '34.251.168.214','34.249.55.110','34.250.248.33'

		#self.run()


	def clientConnectionFailed(self, connector, reason):
		print("Connection failed - goodbye!")
  
	def clientConnectionLost(self, connector, reason):
		print("Connection lost - goodbye!")


	def run(self):
		for i in range(len(self.ips)):
			print(self.ips[i], self.ports[i])
			reactor.connectTCP(self.ips[i], self.ports[i], self, 5, ('localhost', 9000))
		print("starting reactor")
		#reactor.run()


# this connects the protocol to a server running on port 8000
def main(ip, port):#arch, enc, el1, el2, el3, el4, ports):
	f1 = clientFactory(ip, port)#arch, enc, el1, el2, el3, el4, ports)
	f1.run()
   

# this only runs if the module was *not* imported
if __name__ == '__main__':
	if len(sys.argv) <3:
		print('ERROR')
	else:
		main(sys.argv[1], int(sys.argv[2]))#, int(sys.argv[2]),  str(sys.argv[3]),  str(sys.argv[4]),  str(sys.argv[4]),  str(sys.argv[6]),  str(sys.argv[7]))


