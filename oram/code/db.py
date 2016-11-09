from twisted.internet.protocol import Protocol, Factory, ServerFactory
from twisted.internet.defer import Deferred
from twisted.internet import reactor
from os import urandom
import random, sys
from math import log
from collections import namedtuple
from petlib import pack


get = namedtuple('GET', ['name', 'session', 'index', 'int'])
put = namedtuple('PUT', ['name', 'session', 'index', 'int', 'data'])

class DB():
	# Object creating a mix server (client + server) with shuffling and encrypting capabilities
	data =[]

	def __init__(self, name, port, ip, session, nb, size):
		print "DB: init"
		self.name = name
		self.port = port
		self.ip = ip
		self.session = session
		self.prepare_data(nb, size)
		print self.data
		print "DB:init - finished"

		db_factory = DBFact(self)
		db_factory.protocol = DBProto

		reactor.listenTCP(port, db_factory)
		reactor.run()

	def verify_sessionkeys(self, session):
		print "verify",  self.session, session
		res = False
		if self.session == session:
			res=True
		return res

	def get(self, index, interval):
		return pack.encode(self.data[index:index+interval])

	def push(self, index, interval, data):
		data = data.split('-')
		if len(data)!= interval:
			return
		if index > len(self.data)-1:
			return
		if index+interval >len(self.data)-1:
			return
		for i in range(interval):
			self.data[index+i-1]=data[i]
		print self.data

	def prepare_data(self, block_nb, block_size):
		self.data = []
		for i in range(block_nb):
			self.data.extend([chr(97+(i % 25))*(block_size)])
			# self.data.extend([urandom(log(block_nb)), chr((97+i) % 25)*block_size/8])

	
class DBProto(Protocol):
	def __init__(self):
		print "DBP: init"

	def unpack(self,data):
		#return pack.decode(data)
		return (data.rstrip()).split(',')

	def connectionMade(self):
		print "DBP: Connection made"

	def dataReceived(self, data):
        	print "DBP: Receive:", data
		data=self.unpack(data)
		op = data[0].upper()
		if "GET" in op:
			print "get operation"
			g=get(*data)
			if self.factory.db.verify_sessionkeys(g.session):
				print "authorized"
				data = self.factory.db.get(int(g.index), int(g.int))
				self.transport.write(data)
				print "done"
		

		if "PUT" in op:
			print "put operation"
			p=put(*data)
			if self.factory.db.verify_sessionkeys(p.session):
				print "authorized"
				self.factory.db.push(int(p.index), int(p.int), p.data)
				print "done"

		self.transport.loseConnection()
		print "connection closed"

	def connectionLost(self, reason):
        	print "DBP: Connection lost", reason


class DBFact(ServerFactory):
	protocol = DBProto

	def __init__(self, db):
		print "DBF: init"
		self.db = db

	def clientConnectionFailed(self, connector, reason):
	        print 'DBF: Connection failed:', reason.getErrorMessage()
	        self.done.errback(reason)

	def clientConnectionLost(self, connector, reason):
	        print 'DBF: Connection lost:', reason.getErrorMessage()
	        self.done.callback(None)


if __name__ == '__main__':
	if len(sys.argv) <7:
		print "ERROR: you have entered "+len(sys.argv)+" inputs."
	else:
        	db = DB(str(sys.argv[1]), int(sys.argv[2]), sys.argv[3], str(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]))
# name, port, ip, session, nb, size
