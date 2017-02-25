# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
import msgpack
from petlib import pack
import random, string
from twisted.internet import reactor, protocol

datadb=[]

class DB(protocol.Protocol):
    """This is just about the simplest possible protocol"""
    
    def __init__(self):
	print "init", datadb

    def dataReceived(self, data):
	print "data received", data
        "As soon as any data is received, write it back."
	data = pack.decode(data)
	print "data decoded", data
	op, vs, content = data
	send = ""
	if "GET" in op:	
		print "in GET"
		range1, range2, data = content
		if range2 > len(datadb):
			range2=len(data)-1
		send = ["PUT", vs, datadb[range1:range2]]
	if "PUT" in op:
		print "in PUT"
		range1, range2, data = content
		datadb[range1:range2] = data
		send = ["ACK", vs, []]
		print "data now", datadb
	if "ACK" in op:
		self.transport.loseConnection()

	if send != "" :
		print "sending", send
	        self.transport.write(pack.encode(send))
 
class CustomClass:
	def __eq__(self, other):
	        return isinstance(other, CustomClass)
def enc_CustomClass(obj):
	if isinstance(obj, CustomClass):
		return msgpack.ExtType(10, b'')
	raise TypeError("Unknown type: %r" % (obj,))

def dec_CustomClass(code, data):
	if code == 10:
		return CustomClass()
	return msgpack.ExtType(code, data)



def main():
    """This runs the protocol on port 8000"""
    for i in range(9):
	datadb.extend([str(i)*5])
    factory = protocol.ServerFactory()
    factory.protocol = DB
    reactor.listenTCP(8000,factory)
    reactor.run()

# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()

