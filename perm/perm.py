import numpy as np
from random import shuffle, randint, sample
from itertools import combinations

class bucket:
 def __init__(self,size,nb_chunks):
  self.size=size
  self.array= []
  self.nb_chunks=nb_chunks
  self.chunks=[]
  for i in range(nb_chunks):
   self.chunks.extend([[]])

 def fill_all(self, a):
  if len(a) != self.size:
   return
  self.array=[]
  for i in range(self.size):
   self.array.extend([a[i]])
  self.fill_chunks()

 def fill_array(self):
  self.array=[]
  for i in range(self.nb_chunks):
   for j in range(len(self.chunks[i])):
    self.array.extend([self.chunks[i][j]])

 def fill_chunks(self):
  c=0
  self.chunks[0]=[]
  for i in range(len(self.array)):
   if i % (self.size / self.nb_chunks) == 0 and i != 0:
    c=c+1
    self.chunks[c]=[]
   self.chunks[c].extend([self.array[i]])

 def permute_chunks(self):
  a= self.size / self.nb_chunks
  new_chunks = []
  for i in range(self.nb_chunks):
   new_chunks.extend([[]])
  for i in range(self.nb_chunks):
   shuffle(self.chunks[i])
   idx=0
   for j in range(a):
    if j % (a/ self.nb_chunks) == 0 and j != 0:
     idx=idx+1
    new_chunks[idx].extend([self.chunks[i][j]])
  b = randint(0,self.nb_chunks-1)
  print b, self.chunks[b], new_chunks[b]
  self.chunks=new_chunks
  self.fill_array()

 def shuffle_chunks(self):
  shuffle(self.chunks)
  self.fill_array()
  
 def shuffle_chunk(self,i):
  shuffle(self.chunks[i])
  self.fill_array()

 def shuffle_all(self):
  if len(self.array)==0:
    return
  shuffle(self.array)
  self.fill_chunks()


class perm:

 def __init__(self, n,b,c,d,da):
  self.n=n #nb of items
  self.b=b #nb of buckets
  self.c=c #nb of chunks per buckets	

  self.d=d #nb of databases
  self.da=da #nb of compromised ones

  self.vector = range(1,n+1)
  self.bucket = []
  for i in range(self.b):
   self.bucket.extend([[]])
  self.chunk = []
  for i in range(self.b*self.c):
   self.chunk.extend([[]])

 def fill_chunks(self):
  for i in range(self.b*self.c):
   self.fill_chunk(i)

 def fill_chunk(self,i):
  for j in range(i*self.n/(self.c*self.b),(i+1)*self.n/(self.c*self.b)):
   self.chunk[i].extend([self.vector[j]])

 def fill_buckets(self):
  for i in range(self.b):
   self.fill_bucket(i)

 def fill_bucket(self, i):
  for j in range(i*self.n/self.b,(i+1)*self.n/self.b):
   self.bucket[i].extend([self.vector[j]])

 def fill_all(self):
  b=0
  c=0
  for i in range(self.n):
   if i % self.n / self.c == 0 and i != 0:
    c=c+1
   if i % self.n / self.b == 0 and i != 0:
    b=b+1
   self.bucket[b].extend([self.vector[i]])
   self.chunk[c].extend([self.vector[i]])
