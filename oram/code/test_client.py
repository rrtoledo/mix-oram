from os import urandom
from collections import namedtuple
from binascii import hexlify
from copy import copy
import math

from hashlib import sha512, sha1
import hmac

import msgpack

from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn
from petlib.cipher import Cipher
import base64
import petlib.pack
import binascii
from os import urandom


import time
Keys = namedtuple('Keys', ['b', 'iv', 'kmac', 'kenc', 'seed'])
Actor = namedtuple('Act', ['name', 'port', 'host', 'pubk'])


def test( parallel=0 ):
	from client import Client

	G = EcGroup(713)
	o = G.order()
	g = G.generator()
	o_bytes = int(math.ceil(math.log(float(int(o))) / math.log(256)))

	s = (G, o, g, o_bytes)

	mix1privk = Bn.from_binary(base64.b64decode("z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ=="))
	mix1pubk = mix1privk * g

	mix2privk = Bn.from_binary(base64.b64decode("266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA=="))
	mix2pubk = mix2privk * g

	privk = Bn.from_binary(base64.b64decode("DCATXyhAkzSiKaTgCirNJqYh40ha6dcXPw3Pqw=="))
	recpubk = privk * g

	dbprivk = Bn.from_binary(base64.b64decode("/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ=="))
	dbpubk = dbprivk * g

	m1m2 = (mix1privk * G.order().random()) * mix2pubk
	m1db = (mix1privk * G.order().random()) * dbpubk
	m1c = (mix1privk * G.order().random()) * recpubk
	m2db = (mix2privk * G.order().random()) * dbpubk
	m2c = (mix2privk * G.order().random()) * recpubk
	cdb = (privk * G.order().random()) * dbpubk

	pub=[Actor("M1", 8001, "127.0.0.1", (mix1pubk, s)), Actor("M2", 8002, "127.0.0.1", (mix2pubk, s)), Actor("C", 8007, "127.0.0.1", (dbpubk, s)), Actor("DB", 9999, "127.0.0.1", (recpubk, s))]

	print "C"
	receiver = Client('C', 9999, "127.0.0.1", s, privk, recpubk, pub, urandom(24))
	receiver.privk = privk
	receiver.pubk = recpubk
	receiver.group = s
	receiver.shared_secrets = {"M1":m1c, "M2":m2c, "DB": cdb}
	receiver.cascade = parallel

	data = receiver.sendCascade()
	print "cascade -----------------------------------------------------"
	print data

	receiver.keys=[]
	data = receiver.sendParallel()
	print "\nparallel --------------------------------------------------"
	print data

	print "init finished"

