2# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
import msgpack
from petlib import pack
import random, string
from twisted.internet import reactor, protocol
from twisted.internet.protocol import Factory
from twisted.application import service, internet
from os import urandom
import sys
import threading 

class DBProto(protocol.Protocol):
    """This is just about the simplest possible protocol"""
    
    def __init__(self):
	print "init DBProto"

    def dataReceived(self, data):
	print "data received"#, data
        "As soon as any data is received, write it back."
	data = pack.decode(data)
	print "data decoded", data
	op, vs, content = data
	send = ""
	if "GET" in op:	
		print "in GET"
		range1, range2, data = content

		ld = 0
		with self.factory.datalock:
			ld = len(self.factory.data)

		if range2 > ld:
			range2=ld-1
		data=[]
		with self.factory.datalock:
			data=self.factory.data
		print range1, range2, data
		send = ["PUT", vs, data[range1:range2]]
	if "PUT" in op:
		print "in PUT"
		range1, range2, data = content
		with self.factory.datalock:
			for i in range(range1, range2):
				self.factory.data[i] = data[i-range1]
			data = self.factory.data
		send = ["ACK", vs, []]
		print "data now", data
	if "ACK" in op:
		self.transport.loseConnection()

	if send != "" :
		print "sending", send
	        self.transport.write(pack.encode(send))

	def doStart(self):
		print "HEY"
 
class DBServer(Factory):
	protocol = DBProto

	def __init__(self,  port, layered=1):
		print "DBF: init"
		self.port=port
		self.data=[]
		self.datalock= threading.Lock()
		with self.datalock:
			for i in range(9):
				if layered:
					self.data.extend([[urandom(16), str(i)*16]])
				else:
					self.data.extend([str(i)*4])

	def run(self):
		reactor.listenTCP(port, self)
		reactor.run()


	def run(self):
		#Run the MixServer
		print "Run DBServer"
		#tcp_server = internet.TCPServer(self.port, self.mix)	

		#application = service.Application("Mixnode")
		#tcp_server.setServiceParent(application)
		reactor.listenTCP(self.port, self)
		reactor.run()

def main(port, layered):#boolean):
	"""This runs the protocol"""
	db = DBServer(port, layered)
	db.run()  

# this only runs if the module was *not* imported
if __name__ == '__main__':
    main(int(sys.argv[1]), int(sys.argv[2]))

