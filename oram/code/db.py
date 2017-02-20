# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
import msgpack
from petlib import pack
import random, string
from twisted.internet import reactor, protocol


class Echo(protocol.Protocol):
    """This is just about the simplest possible protocol"""
    
    def __init__(self):
	self.data =[]
	for i in range(10):
		self.data.extend([str(i)*5])
	self.data=pack.encode(self.data)
	print 1, self.data

    def dataReceived(self, data):
        "As soon as any data is received, write it back."
	op, vs, content = data
	send = ""
	if "GET" in op:	
		range1, range2 = content
		send = ["PUT", vs, self.data[range1:range2]]
	else if "PUT" in op:
		range1, range2, data = content
		self.data[range1:range2] = data
		send = ["OK", vs, []]
	else:
		send = ["ERR", vs, []]
        self.transport.write(send)

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
    factory = protocol.ServerFactory()
    factory.protocol = Echo
    reactor.listenTCP(8000,factory)
    reactor.run()

# this only runs if the module was *not* imported
if __name__ == '__main__':
    main()

