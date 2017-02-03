from __future__ import division
from random import sample
from math import sqrt, log, ceil

n=10**4   #nb of records
s=int(ceil(sqrt(n))) #stash size
k=int(ceil(log(n)))  #nb dummies per access
t=10**4   #nb of trials

print "starting trials",n,s,k,t


rec = [0]*n
result = [0]*min(n+1,(s*k)+1)
for i in range(t):
 rec = [0]*n
 count = 0
 for l in range(s):
  temp = sample(range(n),k)
  for j in range(k):
   rec[temp[j]] += 1
 for j in range(n):
  if rec[j]!=0:
   count+=1
 result[count]+=1


print "calculating"

for i in range(min(n,s*k)+1):
 result[i]=100*result[i]/t 
 if result[i]!=0:
  print i,

print ""

print "max: ",result.index(max(result)),"out of", len(result)
print result
