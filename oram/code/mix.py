from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.internet.defer import Deferred
from twisted.internet import reactor
import random, sys

#http://stackoverflow.com/questions/3275004/how-to-write-a-twisted-server-that-is-also-a-client
Keys = namedtuple('Keys', ['b', 'iv', 'kmac', 'kenc', 'seed'])
Actor = namedtuple('Mix', ['name', 'port', 'host', 'pubk'])

class Mix():
# Object creating a mix server (client + server) with shuffling and encrypting capabilities

	cascade = True

	def __init__(self, name, port, ip, group, pub):
		print "Mix: init"
		self.name = name 	# Name of the mix
		self.port = port 	# Port of the mix
		self.ip = ip	 	# IP of the mix

		self.group = group 	# G o g o.byte
		self.pubk = ''		# Public key of the mix
		self.privk = ''		# Private key of the mix

		self.pub = pub 		# Servers and client's public keys
		self.shared_secrets = ''# Shared secrets 

		self.s_factory = ServerFact(self)
		reactor.listenTCP(self.port, self.s_factory)
		reactor.run()

	def verifyMeta(self, sender, metadata):
		''' Verify the integrity of a user packet'''
		result = False

		#parse the message
		old_mac = data[0:20]
		old_cipher = data[20:]

		#create mac key
		shared = self.shared_secrests[sender]
		k = KDF(shared.export())
		kmac = k.kmac

		#verify mac
		macproof = hmac.new(kmac, old_cipher, digestmod=sha1).digest()
		if old_mac != macproof:
			return result

		#calculate seed, key and mac, verify inner mac
		db_id, db_key, index, interval, alphas, mac = msgpack.unpackb(msg_b[20:])		
		content = [db_id, db_key, index, interval, alphas]
		macproof2 = hmac.new(kmac, content, digestmod=sha1).digest() 
		if mac == macproof2:
			result = True

		return result

	def createMeta(self, metadata, receiver):
		''' Update the matadata for next node in the Cascade case '''

		#Verify packet integrity
		if !self.verify_meta(metadata):
			return ""

		#Parse message
		db_id, db_key, index, interval, alphas, mac = msgpack.unpackb(metadata[20:])

		#calculate AES key and iv
		k = self.computeAES( self.shared_secrets[receiver] )		

		#calculate new metada
		for i in range(len(alphas)):
			alphas[i] = self.updateAlpha(alphas[i], self.pubk, self.setup)
		meta = [db_id, db_key, index, interval, alphas]
		mac_in = hmac.new(k.kmac, cipher, digestmod=sha1).digest()
		meta = msgpack.packb([db_id, db_key, index, interval, alphas, mac_in]) 

		#encrypt metadata
		cipher = aes_enc_dec(k.kenc, k.iv, meta) 

		#calculate new mac
		mac = hmac.new(self.pub[index+1], cipher, digestmod=sha1).digest()

		#create new message
		cipher = mac + msgpack.packb(ciphertext_metadata)

		return cipher 
			
	def deriveAlphas(self, alphas, sender, r):
		''' Derive the alphas for the different rounds in the Parallel case '''

		#Create all private and public alphas		
		alphas_new = []
		alphas_old = []
		alphas_pub = []
		alpha1 = groupEl1
		alpha2 = groupEl2
		alpha3 = groupEl3
		for i in range(r):
			alphas_new.expend(alpha1)
			alpha1 = self.updateAlpha(alpha1, self.pubk, self.setup)
			alphas_old.expend(alpha2)
			alpha2 = self.updateAlpha(alpha2, self.pubk, self.setup)
			alphas_pub.expend(alpha3)
			alpha2 = self.updateAlpha(alpha2, sender.pubk[0], sender.pubk[1]) 
		return alphas_new, alphas_old, alphas_pub

	def refreshBlocks(self, s_key, blocks):
		''' Refresh blocks encryption with alpha'''
		key, iv = self.computeAES(s_key)
		for i in range(len(blocks)):
			blocks[i] = aes_enc_dec(key, iv, blocks[i])
		return blocks
	
	def permuteBlocks(self, s_seed, way, blocks):
		''' Permute block depending on private (old/new) or public seed '''
		seed = self.computeSeed(s_seed) 
		random.seed(seed)
		if way:
			interval = range(0,len(blocks)-1)
			z = zip(interval, blocks)
			random.shuffle(z)
			z.sort()
			blocks = zip(*z)[1]
		else:
			random.shuffle(blocks)
		return blocks

	def KDF(self, element, idx="A"):
	    ''' The key derivation function for b, iv, keys and seeds '''
	    keys = sha512(element + idx).digest()
	    return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64])


	def computeSharedSecret(self, groupEl, pubk, setup):
		''' Compute shared secret '''
		G, o, g, o_bytes = setup
		xysec = groupEl * pubk
		return shared 

	def computeBinding(self, shared, setup):
		''' Compute new binding (for next mix/round) '''
		G, o, g, o_bytes = setup
		k = KDF(shared.export())
		b = Bn.from_binary(k.b) % o
		return b

	def updateAlpha(self, groupEl, pubk, setup):
		''' Compute new alpha (for next mix/round) '''
		''' should always be used with my pubk and setup '''
		shared = self.computeSharedSecret(groupEl, pubk, setup)
		b = self.computeBinding(shared, setup)
		return b * groupEl

	def computeAES(self, shared):
		''' Compute AES key and iv for eviction '''
		k = KDF(shared.export())
		return k.kenc, k.iv

	def computeSeed(self, shared):
		''' Compute Seed for eviction '''
		k = KDF(shared.export())
		return k.seed

	def computeMAC(self, shared):
		''' Compute MAC for eviction '''
		k = KDF(shared.export())
		return k.kmac

	def aes_enc_dec(self, key, iv, data):
		''' AES Enc/Dec '''
		aes = Cipher("AES-128-CTR")
		enc = aes.enc(key, iv)
		output = enc.update(data)
		output += enc.finalize()
		return output

class ServerProto(Protocol):

	def __init__(self):
		print "SP: init"

	def connectionMade(self):
		print "SF: Connection made"
		self.factory.s_protos.append(self)

	def dataReceived(self, data):
		print "SF: Data received", data
		
		print "encrypt"
		print "sort"
		#cipher = self.mix.encrypt(data)
		#processed_data = self.mix.sort(cipher)
		pdata = data +"_processedS_"
		print pdata
		c_factory = ClientFact(self, pdata)
		c_factory.protocol = ClientProto
		#reactor.connectTCP(self.pub[][], self.pub[][], c_factory) #TODO
		reactor.connectTCP("127.0.0.1", int(self.factory.mix.pub), c_factory)

		#c_factory.c_proto.transport.write(data+"_processedS_")
		#print "data written"

	def connectionLost(self, reason):
	        print "SF: Connection lost", reason

	def returnData(self, data):
		self.transport.write(data+"_fromS2_") #TODO
		#self.flush()
		self.transport.loseConnection()

	def processData(self, data):
		print "in processData"
		#Parse & Calculate
		#Encrypt
		#Permute

class ServerFact(Factory):
	protocol = ServerProto

	def __init__(self, mix):
		print "SF: init"
		self.mix = mix
		self.s_protos = []

class ClientProto(Protocol):

	def __init__(self):
		print "CP: init"

	def connectionMade(self):
		print "CP: Connection made"
		self.factory.c_proto = self
		self.transport.write(self.factory.data)

	def dataReceived(self, data):
        	print "CP: Receive:", data
		self.factory.s_proto.returnData(data+"_processedC_")
		self.transport.loseConnection()

	def connectionLost(self, reason):
        	print "CP: Connection lost", reason

class ClientFact(ClientFactory):
	protocol = ClientProto

	def __init__(self, s_proto, data):
		print "CF: init"
		self.done = Deferred()
		self.s_proto = s_proto
		self.c_proto = None
		self.data = data

	def clientConnectionFailed(self, connector, reason):
	        print 'CF: Connection failed:', reason.getErrorMessage()
	        self.done.errback(reason)

	def clientConnectionLost(self, connector, reason):
	        print 'CF: Connection lost:', reason.getErrorMessage()
	        self.done.callback(None)


if __name__ == '__main__':
	if len(sys.argv) <6:
		print "ERROR: you have entered "+len(sys.argv)+" inputs."
	else:
   
        	mix = Mix(str(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
		# name port ip group pub
