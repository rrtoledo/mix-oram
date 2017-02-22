from __future__ import print_function
from collections import namedtuple
from twisted.internet import reactor, protocol
from twisted.internet.defer import Deferred
from os import urandom
from petlib import pack
import sys
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

    def __init__(self):
	print("CF: init")
	self.done = Deferred()
	self.c_proto = None
        self.data = pack.encode(["STT", int(urandom(2).encode('hex'),16), [[ Actor("DB", "127.0.0.1", 8000, ""), 3], [], [Actor("M1", "127.0.0.1",8001, ""), Actor("M2", "127.0.0.1",8002, ""), Actor("M3", "127.0.0.1", 8003, "")]] ])

    def clientConnectionFailed(self, connector, reason):
        print("Connection failed - goodbye!")
        reactor.stop()
    
    def clientConnectionLost(self, connector, reason):
        print("Connection lost - goodbye!")
        reactor.stop()


# this connects the protocol to a server running on port 8000
def main(port):
    f1 = clientFactory()
    reactor.connectTCP("localhost", port, f1,5, ('localhost', 9000))
    reactor.run()
   

# this only runs if the module was *not* imported
if __name__ == '__main__':
    if len(sys.argv) <2:
	print('ERROR')
    else:
	main(int(sys.argv[1]))


