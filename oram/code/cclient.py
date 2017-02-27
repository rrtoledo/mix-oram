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
        print("Server said:", data, self.transport.getPeer())
        self.transport.loseConnection()
    
    def connectionLost(self, reason):
        print("connection lost")

class clientFactory(protocol.ClientFactory):
    protocol = Client

    def __init__(self, arch, enc, el1, el2, el3, el4, ports):
	print("CF: init")
	self.done = Deferred()
	self.c_proto = None
	
	self.G = EcGroup(713)
	self.o = self.G.order()
	self.g = self.G.generator()
	self.o_bytes = int(math.ceil(math.log(float(int(self.o))) / math.log(256)))
	self.data = ["STT", int(urandom(2).encode('hex'),16), [ Actor("DB", "127.0.0.1", 8000, ""), 3]]
	if arch:
	    if enc:
		self.data[2].extend([["", Bn.from_binary(base64.b64decode(el2))]])
		
	    else:
		self.data[2].extend([[Bn.from_binary(base64.b64decode(el2)), Bn.from_binary(base64.b64decode(el2))]])
	else:
	    if enc:
		self.data[2].extend([["", Bn.from_binary(base64.b64decode(el2))],[["", Bn.from_binary(base64.b64decode(el4))]]])
	    else:
		self.data[2].extend([ [Bn.from_binary(base64.b64decode(el1)), Bn.from_binary(base64.b64decode(el2))], [Bn.from_binary(base64.b64decode(el3)), Bn.from_binary(base64.b64decode(el4))]])
	actors=[]
	for i in range(len(ports)):
		    actors.extend([Actor("M"+str(i), "127.0.0.1", 8001+i, "")])
	self.data[2].extend([[actors]])

    def test(self):

        self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], ["", Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ]) # cascade layered


        #self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], [Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g, Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ]) #cascade rebuild


	#self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], ["", Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], ["", Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g], 9, 2, [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ]) #parallel layered

        #self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], [Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*g, Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))*self.g], [Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*g, Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))*self.g], 9, 10,  [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ]) #parallel rebuild


    def clientConnectionFailed(self, connector, reason):
        print("Connection failed - goodbye!")
        reactor.stop()
    
    def clientConnectionLost(self, connector, reason):
        print("Connection lost - goodbye!")
        reactor.stop()


# this connects the protocol to a server running on port 8000
def main(arch, enc, el1, el2, el3, el4, ports):
    f1 = clientFactory(arch, enc, el1, el2, el3, el4, ports)
    for i in range(len(ports)):
	reactor.connectTCP("localhost", port, f1, 5, ('localhost', 9000))
    reactor.run()
   

# this only runs if the module was *not* imported
if __name__ == '__main__':
    if len(sys.argv) <2:
	print('ERROR')
    else:
	main(int(sys.argv[1]), int(sys.argv[2]),  str(sys.argv[3]),  str(sys.argv[4]),  str(sys.argv[4]),  str(sys.argv[6]),  str(sys.argv[7]))


