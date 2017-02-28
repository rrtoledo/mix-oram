import os
import sys
current_path = os.getcwd()
print "Current Path: %s" % current_path
sys.path += [current_path]

from mix import MixServer
from twisted.protocols import basic
from twisted.internet import stdio, reactor
from twisted.application import service, internet
import sys
import petlib.pack
from binascii import hexlify
import os.path


#if not (os.path.exists("secretMixnode.prv") and os.path.exists("publicMixnode.bin")):
#	raise Exception("Key parameter files not found")

# Read crypto parameters
#setup = format3.setup()
#G, o, g, o_bytes = setup
#secret = petlib.pack.decode(file("secretMixnode.prv", "rb").read())

print "HEYYY"
name=""
ip=""
port= 0
key=""
arch=0
layered=0

try:
	#data = file("publicMixnode.bin", "rb").read()
	#_, name, port, host, _ = petlib.pack.decode(data)

	# Create the mix
	mix = MixServer("M1", "localhost", 8001, 0, 0, 0)
	print "mix created"
	#mix.readInData('example.db')
	#print "Public key: " + hexlify(mix.pubk.export())
	
	tcp_server = internet.TCPServer(8001, mix)	

	# Create a cmd line controller
	# stdio.StandardIO(MixnodeEcho(mix))

	application = service.Application("MixServer")
	tcp_server.setServiceParent(application)
	
except Exception, e:
	print str(e)



