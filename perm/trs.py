from __future__ import division
from math import factorial as f

class perm():

 def comb(self, n,k):
  if k > n:
   return 0
  else:
   res= f(n)/(f(k)*f(n-k))
   return res

 def p_k(self, n,t,k):
  result=0
  bound = min(t+1,max(1,k+1),max(1,n-k))
  for i in range(1,bound+1):
   fact = self.comb(t,i)
   res_L = self.comb(k+1,i) / self.comb(n,i)
   res_R = self.comb(n-k,i) / self.comb(n,i)
   res = fact * res_L * res_R
   #print fact, res_L, res_R
   #print "p_"+str(k)+":", "i="+str(i), res
   result+=res
  #print "pk",k, result
  return result

 def expectation(self, n,t):
  result=0
  for i in range(n):
   res= 1/(self.p_k(n,t,i))
   #print "1/p"+str(i), res
   result+=res
  #print ""
  return result   
