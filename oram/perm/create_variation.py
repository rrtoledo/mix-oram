from __future__ import division
from math import log, log10
from trs import perm
import time
import sys

if len(sys.argv)<3 or int(sys.argv[2])>int(sys.argv[1]):
 print "python create_graph_AS_DR.py $n $t"
 if len(sys.argv)<3:
  print "You have entered "+str(len(sys.argv)-1)+' arguments.'
 else:
  print "n =",sys.argv[1],", t =",sys.argv[2]
 sys.exit("Error")


n= int(sys.argv[1])
t= int(sys.argv[2])

f=open("var_n"+str(n)+"_t"+str(t)+".dat","w")
f.write("# x \t expectation \t 2/t n log(n) \t diff \ ratio \r\n")

a=perm()


ti = time.time()
for x in range(1,t):
 res1 = a.expectation(n,x)
 res2 = 2.0/x * n*log(n)
 diff = res1-res2
 ratio = abs(res1/res2)
 f.write(str(x)+"\t"+str(res1)+"\t"+str(res2)+"\t"+str(diff)+"\t"+str(ratio)+"\r\n")
 elapsed = time.time()-ti
 print str(x/t)+"%", "-------", elapsed
f.close()

