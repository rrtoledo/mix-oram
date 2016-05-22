from random import randint, seed, shuffle
from sys import maxint

class Shuffle:
 def __init__(self):
  self.int_seed = randint(0, maxint)
  seed(self.int_seed)

 def random_shuffle(self, seq):
  new_seq=list(seq)
  if len(seq)!=0:
    shuffle(seq)
  return new_seq

 def fisher_yates(self, seq):
  new_seq = list(seq)
  if len(seq)!=0:
   for i in range(len(seq)):
    j = randint(0,i)
    a = new_seq[i]
    new_seq[i] = new_seq[j]
    new_seq[j] = a
  return new_seq
