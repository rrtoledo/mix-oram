# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
import msgpack
from petlib import pack
import random, string
from twisted.internet import reactor, protocol
from twisted.internet.protocol import Factory
from twisted.application import service, internet
from os import urandom
import threading
import sys
import threading 
from math import ceil, log, floor


class DBProto(protocol.Protocol):
    """This is just about the simplest possible protocol"""
    
    def __init__(self):
	print "init DBProto"


    def connectionLost(self, reason):
       	print "connection lost", reason

    def dataReceived(self, data):
	print "DBP Data Received"#, data

	data = pack.decode(data)
	name, op, vs, turn, option, nbpack, totpack, content = data
	print "data decoded", name, op, vs, turn, option, nbpack, totpack
	print data
	range1, range2 = option
	key=name+str(vs)+str(turn)

	with self.factory.sessionlock:
		if key not in self.factory.sessions.keys():
			if "GET" in op:
				totpack = int(ceil((range2-range1)/float(self.factory.maxrec)))
				nbpack = 0
			self.factory.sessions[key]=[op,nbpack,totpack,range1,range2]
			print "adding", key, "with",op,nbpack,totpack,range1,range2

	send = ""

	if "GET" in op:	
		print "in GET", (name,vs,turn)
		
		data=[]
		print range1,range2
		print nbpack, self.factory.maxrec
		with self.factory.datalock:
			data=self.factory.data[range1+nbpack*self.factory.maxrec:min(range1+(nbpack+1)*self.factory.maxrec, range2)]
		print range1, range2#, data
		send = [self.factory.name, "PUT", vs, turn, "", 0, totpack, data ]


	if "PUT" in op:
		print "in PUT",(name,vs,turn)
		with self.factory.datalock:
			for i in range( len(content) ):
				print "PUT", i+range1, content[i]
				self.factory.data[i+range1] = content[i]
		if nbpack != totpack-1 :
			send = [self.factory.name, "ACK", vs, turn, "", nbpack, totpack, ""]
		else:
			send = [self.factory.name, "END", vs, turn, "",  nbpack, totpack, ""]
			with self.factory.sessionlock:
				del self.factory.sessions[key]
		print "data now"#, data

	if "ACK" in op and "GET" in self.factory.sessions[key]:
		with self.factory.datalock:
			data=self.factory.data[range1+nbpack*self.factory.maxrec:min(range1+(nbpack+1)*self.factory.maxrec, range2)]
		send = [self.factory.name, "PUT", vs, turn, "", nbpack, totpack, data ]

	if "END" in op:
		print "in END", key
		with self.factory.sessionlock:
			del self.factory.sessions[key]
		self.transport.loseConnection()

	if send != "" :
		print "sending", key#, send
		print self.factory.sessions.keys()
		with self.factory.sessionlock:
			if key in self.factory.sessions.keys():
				self.factory.sessions[key][1]+=1
	        self.transport.write(pack.encode(send))

	def doStart(self):
		print "Starting !"
 
class DBServer(Factory):
	protocol = DBProto

	def __init__(self,  port, layered, n, size, m):
		print "DBF: init"
		self.name="DB"
		self.port=port
		self.data=[]
		self.datalock= threading.Lock()
		nn = int(ceil(n/float(m))*m)
		with self.datalock:
			for i in range(nn):
				temp=""
				if i==0:
					temp=str(0)*size
				else:
					power = int(floor(log(10, nn)))
					temp=str(0)*(size-power-1)+str(i)
				if layered:
					self.data.extend([[urandom(16), temp]])#urandom(size)]])
				else:
					self.data.extend([temp])#[urandom(size)])

		self.size= sys.getsizeof(self.data[0])
		self.maxrec = int(floor(200000.0/self.size))
		
		self.sessions={}
		self.sessionlock=threading.Lock()


		print "data ready", len(self.data)#, self.data

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

def main(port, layered, n, size, m):#boolean):
	"""This runs the protocol"""
	db = DBServer(port, layered, n, size, m)
	db.run()  

# this only runs if the module was *not* imported
if __name__ == '__main__':
    main(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))

