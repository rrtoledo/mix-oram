from petlib.ec import EcGroup, EcPt
from random import randint

class EG:
 def __init__(self): 
  self.EG_keys={}

 def create_EG(self, name, nid = 713):
  G = EcGroup(nid)
  g= G.generator()
  o = G.order()

  prkey = o.random()  
  pbkey = prkey * g
  params = (G,g,o)
  self.store_EG(name, prkey, pbkey, params)

 def store_EG(self, name, prv, pbc, params):
  if len(name)==0:
   return
  if name in self.EG_keys.keys():
   ctr = sum( name in key for key in self.EG_keys.keys()) 
   name = name+"-"+str(ctr)
   print "Name already chosen, new name is "+name
  self.EG_keys.update({name: [prv, pbc, params]})
 
 def enc_EG(self, name, plain):
  toencrypt = self.formater(plain)
  G, g, o = self.EG_keys[name][2]
  k = o.random()
  results=[]
  for i in range(len(toencrypt)):
   a = k * g
   b = k * self.EG_keys[name][1] + plain * g
   res = (a, b)
   results.extend([(a,b)])
  return results

 def randomize(self, name, pub, ciphers):
  results=[]
  for i in range(len(ciphers)):
   zero = self.enc_EG(self.EG_keys[name][2], pub, 0)
   res = self.add(cipher, zero)
   results.extend([res])
  return results

 def dec_EG(self, name, ciphers):
  _, g, o = self.EG_keys[name][2]
  priv = self.EG_keys[name][0]
  table = self.make_table(self.EG_keys[name][2])
  results=""
  for i in range(len(ciphers)):
   a, b = ciphers[i]
   plain = b + (-priv * a)
   results.extend(table[plain])
  plaintext = self.reformater(results)
  return plaintext

 def make_table(self, params):  #make a decryption table
  _, g, o = params
  table = {}
  for i in range(-1000, 1000):
   table[i*g] = i
  return table

 def add(self, c1, c2):
  a1, b1 = c1
  a2, b2 = c2
  return (a1 + a2, b1 + b2)

 def mul(self, c1, val):
  a1, b1 = c1
  return (val*a1, val*b1)



 def formater(self, m):
  results = self.stringtobit(m)
  for i in range(len(results)):
   results[i] = self.bittoint(results[i])
  return results

 def reformater(self, ciphers):
  result = ''
  for bit in ciphers:
   result += self.inttobit(bit)
  m= self.bittostring(result)
  return m

 def stringtobit(self, s):
  result =''
  for c in s:
   bits = bin(ord(c))[2:]
   bits = '00000000'[len(bits):] + bits
   for b in bits:
    result += str(b)
  results= [ result[i:i+8] for i in range(0, len(result), 8) ]
  return results

 def bittoint(self, s):
  return int(s, 2)

 def inttobit(self, i):
  return '{0:08b}'.format(i)

 def bittostring(self, s):
  chars = []
  for b in range(len(s) / 8):
   byte = s[b*8:(b+1)*8]
   chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
  return ''.join(chars)
