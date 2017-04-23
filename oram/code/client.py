from __future__ import print_function, division
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

	def __init__(self,ip, port, n,m):#, arch, enc, el1, el2, el3, el4, ports):
		print("CF: init")
		self.done = Deferred()
		self.c_proto = None
		self.name = "C"

		self.ip = ip # ['34.251.168.214','34.249.66.110','34.250.248.33']
		self.port = port#[8001,8002,8003]
		self.n=n
		self.m=m
	
		self.G = EcGroup(713)
		self.o = self.G.order()
		self.g = self.G.generator()
		self.o_bytes = int(math.ceil(math.log(float(int(self.o))) / math.log(256)))

		nn = int(math.ceil(self.n/self.m)*self.m)

		#self.data = pack.encode([self.name, "STT", 9842, -1, "", 0, 1, [1, 1, [[ Actor("DB", "127.0.0.1", 8000, ""), int(nn/self.m)], ["", Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], nn, 1, [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]]]]) # cascade layered


		self.data = pack.encode([self.name, "STT", 1342, -1, "", 0, 1, [1, 0, [[ Actor("DB", "127.0.0.1", 8000, ""), int(nn/self.m)], [Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g, Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], nn, 1, [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]]]]) #cascade rebuild

		#rounds= int(math.ceil(m *math.log(math.sqrt(nn)) /2))
		#self.data = pack.encode([self.name, "STT", 98621, -1, "", 0, 1, [0, 1, [[ Actor("DB", "127.0.0.1", 8000, ""), int(nn/self.m)], ["", Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], ["", Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g], nn, rounds, [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]]]]) #parallel layered

		#rounds= int(math.ceil(4 * m *(math.log(nn)+1)))
		#self.data = pack.encode([self.name, "STT", 91864, -1,"",  0, 1, [0,0,[[ Actor("DB", "localhost", 8000, ""), int(nn/self.m)], [Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g, Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], [Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g, Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g], nn, rounds,  [Actor("M1", "localhost",8001, ""), Actor("M2", "localhost",8002, ""), Actor("M3", "localhost", 8003, "")]]]]) #parallel rebuild '34.251.168.214','34.249.55.110','34.250.248.33'

		print(nn/self.m, self.m, nn, int(math.ceil(2*self.m*math.log(nn))), math.log(nn))
		
		#self.run()


	def clientConnectionFailed(self, connector, reason):
		print("Connection failed - goodbye!", reason)
  
	def clientConnectionLost(self, connector, reason):
		print("Connection lost - goodbye!", reason)


	def run(self):
		print(self.ip, self.port)
		reactor.connectTCP(self.ip, self.port, self, 10)
		print("starting reactor")
		reactor.run()


# this connects the protocol to a server running on port 8000
def main(ip, port, n, m):#arch, enc, el1, el2, el3, el4, ports):
	f1 = clientFactory(ip, port, n, m )#arch, enc, el1, el2, el3, el4, ports)
	f1.run()
   

# this only runs if the module was *not* imported
if __name__ == '__main__':
	if len(sys.argv) <5:
		print('ERROR', len(sys.argv))
	else:
		main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]),  int(sys.argv[4]))#,  str(sys.argv[4]),  str(sys.argv[4]),  str(sys.argv[6]),  str(sys.argv[7]))


