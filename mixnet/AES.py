from petlib.cipher import Cipher
from Crypto.Cipher import DES3
from os import urandom

class AES:
 def __init__(self): 
  self.AES_keys={}
  self.modes = ["gcm", "CTR", "CBC", "CFB"]

 def create_AES(self, name, mode, key_length):
  aes_key = urandom(key_length/8)
  aes_iv  = urandom(key_length/8)
  self.store_AES(str(name), mode.lower(), key_length, aes_key, aes_iv)

 def store_AES(self, name, mode, key_length, aes_key, aes_iv):

  if len(name)==0:
   return
  if name in self.AES_keys.keys():
   ctr = sum( name in key for key in self.AES_keys.keys()) 
   name = name+"-"+str(ctr)
   print "Name already chosen, new name is "+name

  aes_mode=mode
  if "GCM" in mode.upper():
   aes_mode = self.modes[0]
  elif mode.upper() in self.modes:
   aes_mode = mode.upper()
  else:
   print "Error: mode not recognized, available mode : ", self.modes
   return

  if key_length not in [128, 192, 256]:
   print "Error: the key must be 128, 192 or 256 bit long."
   return

  self.AES_keys.update({name: [aes_mode, key_length, aes_key, aes_iv]})

 def enc_AES(self, name, message):
  aes_list = self.AES_keys[name]
  if "gcm" in aes_list[0] :
    aes = Cipher("aes-"+str(aes_list[1])+"-"+aes_list[0])
    ciphertext, tag = aes.quick_gcm_enc(aes_list[2], aes_list[3], message)
    return ciphertext, tag
  else:
   aes = Cipher("AES-"+str(aes_list[1])+"-"+aes_list[0])
   enc = aes.enc(aes_list[2], aes_list[3])
   ciphertext = enc.update(message)
   ciphertext += enc.finalize()
   return ciphertext

 def dec_AES(self, name, ciphertext, tag=None):
  aes_list = self.AES_keys[name]
  plaintext = ""
  if "gcm" in aes_list[0] :
    aes = Cipher("aes-"+str(aes_list[1])+"-"+aes_list[0])
    plaintext = aes.quick_gcm_dec(aes_list[2], aes_list[3], ciphertext, tag)
  else:
   aes = Cipher("AES-"+str(aes_list[1])+"-"+aes_list[0])
   dec = aes.dec(aes_list[2], aes_list[3])
   plaintext = dec.update(ciphertext)
   plaintext += dec.finalize()
  return plaintext

