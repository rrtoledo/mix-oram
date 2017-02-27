from mix import Mix
from cclient import Client
from db import DB
import base64
import math
from petlib.cipher import Cipher 
from hashlib import sha512
from petlib.ec import EcGroup
from petlib.ec import EcPt
from petlib.bn import Bn

import pytest

def test_aes_enc_dec():
	from os import urandom

	aes = Cipher("AES-128-CTR")
	key = urandom(16)
	iv = urandom(16)
	enc = aes.enc(key, iv)
	ipt = "Hello"

	ciphertext = enc.update(ipt)
	ciphertext += enc.finalize()

	dec = aes.enc(key, iv)
	plaintext = dec.update(ciphertext)
	plaintext += dec.finalize()

	assert ipt == plaintext


def test_cascadeLayered():

	G = EcGroup(713)
	o = G.order()
	g = G.generator()
	o_bytes = int(math.ceil(math.log(float(int(o))) / math.log(256)))
	s = (G, o, g, o_bytes)

	db = DB(1)

	mix1 = Mix("M1", "127.0.0.1", 8001, "z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ==", 1, 1)
	mix1.transport = proto_helpers.FakeDatagramTransport()
	mix2 = Mix("M2", "127.0.0.1", 8002, "266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA==", 1, 1)
	mix3 = Mix("M3", "127.0.0.1", 8003, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", 1, 1)

	client = Client(0, 0, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==")

#def test_cascadeRebuild():
#
#	G = EcGroup(713)
#	o = G.order()
#	g = G.generator()
#	o_bytes = int(math.ceil(math.log(float(int(o))) / math.log(256)))
#
#	s = (G, o, g, o_bytes)
#	mix1 = Mix("M1", "127.0.0.1", 8001, "z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ==", 1, 0)
#
#	mix2 = Mix("M2", "127.0.0.1", 8002, "266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA==", 1, 0)
#
#	mix3 = Mix("M3", "127.0.0.1", 8003, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", 1, 0)
#	
#	db = DB(0)
#
#	client = Client(1, 0, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==")
#
#	datadb = []
#	for i in range(9):
#	    datadb.extend([str(i)*16])
#
#	assert db.datadb == datadb

#def test_parallelLayered():
#
#	G = EcGroup(713)
#	o = G.order()
#	g = G.generator()
#	o_bytes = int(math.ceil(math.log(float(int(o))) / math.log(256)))
#
#	s = (G, o, g, o_bytes)
#	mix1 = Mix("M1", "127.0.0.1", 8001, "z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ==", 0, 1)
#
#	mix2 = Mix("M2", "127.0.0.1", 8002, "266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA==", 0, 1)
#
#	mix3 = Mix("M3", "127.0.0.1", 8003, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", 0, 1)
#	
#	db = DB(1)
#
#	client = Client(0, 1, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", "DCATXyhAkzSiKaTgCirNJqYh40ha6dcXPw3Pqw==")
#

#def test_parallelRebuild():
#
#	G = EcGroup(713)
#	o = G.order()
#	g = G.generator()
#	o_bytes = int(math.ceil(math.log(float(int(o))) / math.log(256)))
#
#	s = (G, o, g, o_bytes)
#	mix1 = Mix("M1", "127.0.0.1", 8001, "z7yGAen5eAgHBRB9nrafE6h9V0kW/VO2zC7cPQ==", 0, 0)
#
#	mix2 = Mix("M2", "127.0.0.1", 8002, "266YjC8rEyiEpqXCNXCz1qXTEnwAsqz/tCyzcA==", 0, 0)
#
#	mix3 = Mix("M3", "127.0.0.1", 8003, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", 0, 0)
#	
#	db = DB(0)
#
#	client = Client(0, 0, "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", "/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==", "DCATXyhAkzSiKaTgCirNJqYh40ha6dcXPw3Pqw==", "DCATXyhAkzSiKaTgCirNJqYh40ha6dcXPw3Pqw==")

