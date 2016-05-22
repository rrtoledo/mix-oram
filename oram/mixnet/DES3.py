from Crypto.Cipher import DES3
from os import urandom

class TDES:
 def __init__(self): 
  self.DES3_keys={}
  self.BS = DES3.block_size #in bytes
  self.mode=["", "ECB", "CBC", "CFB", "", "OFB", "CTR"]
  self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS) 
  self.unpad = lambda s : s[:-ord(s[len(s)-1:])]

 def create_DES3(self, name, mode, key_length):
  if key_length not in DES3.key_size:
   print "The key size must be 16 or 24 bytes"
   return
  des_key = urandom(key_length)
  des_iv  = urandom(self.BS)
  self.store_DES3(str(name), mode, key_length, des_key, des_iv)

 def store_DES3(self, name, mode, key_length, des_key, des_iv):
  des_name = name
  if name != "" and name in self.DES3_keys.keys():
   ctr = sum( name in key for key in self.DES3_keys.keys()) 
   des_name = name+"-"+str(ctr)
   print "Name: "+name
  des_mode = mode
  if str(mode).upper() not in self.mode:
   print "Error: mode not recognized. Available modes: ECB, CBC, CFB, CTR"
   return
  else:
   des_mode= self.mode.index(str(mode).upper())
  des = DES3.new(des_key, des_mode, des_iv)
  self.DES3_keys.update({name: [des]})

 def enc_DES3(self, name, message):
  if name not in self.DES3_keys.keys():
   print "Key not found"
   return
  des = self.DES3_keys[name]
  des_message=message
  if des_list[0] in {1,2,3,5}:
   des_message = self.pad(message)
  ciphertext = des.encrypt(des_message)
  return ciphertext

 def dec_DES3(self, name, ciphertext, tag=None):
  if name not in self.DES3_keys:
   print "Key not found"
   return
  des_list = self.DES3_keys[name]
  plaintext = ""
  des = DES3.new(des_list[2], des_list[0], des_list[3])
  plaintext = des.decrypt(ciphertext)
  if des_list[0] in {1,2,3,5}:
   plaintext=self.unpad(plaintext)
  return plaintext
