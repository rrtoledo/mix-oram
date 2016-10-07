py # format 3
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

import time
Keys = namedtuple('Keys', ['b', 'iv', 'kmac', 'kenc', 'seed'])
Actor = namedtuple('Mix', ['name', 'port', 'host', 'pubk'])

def setup():
    ''' Setup the parameters of the mix crypto-system '''
    G = EcGroup()
    o = G.order()
    g = G.generator()
    o_bytes = int(math.ceil(math.log(float(int(o))) / math.log(256)))
    return G, o, g, o_bytes

def KDF(element, idx="A"):
    ''' The key derivation function for b, iv, keys and seeds '''
    keys = sha512(element + idx).digest()
    return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64], keys[64:80])


def computeSharedSecrets(sender, path, setup):
	G, o, g, o_bytes = setup
	Bs = [] # list of blinding factors
	pubs = [] # list of public values shared between Client and mix nodes
	shared_secrets = [] # list of shared secret keys between Client and each mixnode

	pubs = [sender.pubk]
	prod_bs = Bn(1)
	
	for i, node in enumerate(path):
		xysec = (sender.privk * prod_bs) * node.pubk
		shared_secrets.append(xysec)

		# blinding factors
		k = KDF(xysec.export())
		b = Bn.from_binary(k.b) % o
		Bs.append(b)
		prod_bs = (b * prod_bs) % o
		pubs.append(prod_bs * sender.pubk)

	return Bs, pubs, shared_secrets



# ------------------------TESTS-----------------------------
import pytest


def test_paddString():
	assert paddString("A", 10) == "A000000000"


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


def test( parallel=0 ):
	from mix import Mix
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

	dbprivk = Bn.from_binary(base64.b64decode("/m8A5kOfWNhP4BMcUm7DF0/G0/TBs2YH8KAYzQ==")
	dbpubk = senprivk * g

	m1m2 = (mix1privk * G.order().random()) * mix2pubk
	m1db = (mix1privk * G.order().random()) * dbpubk
	m1c = (mix1privk * G.order().random()) * recpubk
	m2db = (mix2privk * G.order().random()) * dbpubk
	m2c = (mix2privk * G.order().random()) * recpubk
	cdb = (privk * G.order().random()) * dbpubk

	pub=[Actor("M1", 8000, "127.0.0.1", (mix1pubk, s)), Actor("M2", 8001, "127.0.0.1", (mix2pubk, s)), Actor("C", 8007, "127.0.0.1", (dbpubk, s)), Actor("DB", 9999, "127.0.0.1", (recpubk, s))]

	mix1 = Mix("M1", 8000, "127.0.0.1", s, pub)
	mix1.privk = mix1privk
	mix1.pubk = mix1pubk
	mix1.group = s
	mix1.shared_secrets = {"C":m1c, "M2":m1m2 , "DB":m1db}

	mix2 = Mix("M2", 8001, "127.0.0.1", s, pub)
	mix2.privk = mix2privk
	mix2.pubk = mix2pubk
	mix2.group = s
	mix2.shared_secrets = {"C":m2c, "M2":m1m2, "DB":m2db}

	receiver = Client('C', 9999, "127.0.0.1", s, pub)
	receiver.privk = privk
	receiver.pubk = recpubk
	receiver.group = s
	receiver.shared_secrets = {"M1":m1c, "M2":m2c, "DB": cdb}

	db = DB("DB", 8007, "127.0.0.1", s, pub)
	db.privk = dbprivk
	db.pubk = dbpubk
	db.group = s
	db.share_secrets = {"M1":m1db, "M2":m2db, "C": cdb}

