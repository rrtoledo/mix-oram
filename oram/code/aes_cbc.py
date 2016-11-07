from time import time
from petlib.cipher import Cipher
from os import urandom

class AES_CBC:

 def __init__(self, sec=128):
  self.aes=Cipher("AES-"+str(sec)+"-CBC")
  self.key = urandom(sec/8)
  self.ctr_iv = urandom(sec/8)

 def aes_enc_dec(self, data):
  ''' AES Enc/Dec '''
  aes = Cipher("AES-128-CBC")
  enc = aes.enc(self.key, self.ctr_iv)
  output = enc.update(data)
  output += enc.finalize()
  return output

