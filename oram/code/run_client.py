import os
import sys
current_path = os.getcwd()
print "Current Path: %s" % current_path
sys.path += [current_path]

from client import clientFactory
from twisted.protocols import basic
from twisted.internet import stdio, reactor
from twisted.application import service, internet

import petlib.pack
from binascii import hexlify
import os.path
from time import sleep

try:
	#data = file("publicMixnode.bin", "rb").read()
	#_, name, port, host, _ = petlib.pack.decode(data)


	#mix.readInData('example.db')
	#print "Public key: " + hexlify(mix.pubk.export())
	
	ips=['localhost','localhost','localhost']
	ports = [8001, 8002, 8003]

	client = clientFactory(ips, ports)

	tcp_client = internet.TCPClient('localhost', 9000, client)	
	application = service.Application("Client")	
	tcp_client.setServiceParent(application)


	# Create a cmd line controller
	# stdio.StandardIO(MixnodeEcho(mix))

	
	
except Exception, e:
	print str(e)



