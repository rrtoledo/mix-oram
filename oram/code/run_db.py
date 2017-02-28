import os
import sys
current_path = os.getcwd()
print "Current Path: %s" % current_path
sys.path += [current_path]

from db import DBServer
from twisted.protocols import basic
from twisted.internet import stdio, reactor
from twisted.application import service, internet

import petlib.pack
from binascii import hexlify
import os.path


try:

	# Create the db
	db = DBServer(8000, 0)
	#mix.readInData('example.db')
	#print "Public key: " + hexlify(mix.pubk.export())
	
	tcp_server = internet.TCPServer(8000, db)	

	# Create a cmd line controller
	# stdio.StandardIO(MixnodeEcho(mix))

	application = service.Application("DB")
	tcp_server.setServiceParent(application)
	
except Exception, e:
	print str(e)



