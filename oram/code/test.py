import random

def permute(seed, data, inverse):
	random.seed(seed)
	perm = random.sample(range(len(data)),len(data))
	temp=[]
	if not inverse:
		for i in range(len(perm)):
			temp.extend([data[perm[i]]])
	else:
		zipped = zip(perm, data)
		zipped.sort(key= lambda t: t[0])
		temp = list(zip(*zipped)[1])
	return temp

def permute_global(seed, n, m, index, inverse):
	random.seed(seed)
	tosend=[]
	temp=permute(seed, range(1,n), inverse)	
	tosend = split(temp, n/m)			
	for i in range(len(tosend)):
		tosend[i]= [tosend[i][j] for j in range(len(tosend[i])) if tosend[i][j] in range(index*n/m, (index+1)*n/m)]
	return tosend
	
def split(tosplit, k):
	return [tosplit[i:i+k] for i in range(0, len(tosplit), k)]		

a= range(1,26)
seed= 1248691
n=41
m=4
k=n/m

print "a", a
p = permute(seed,a,0)
print "p", p
pp = permute(seed,a,1)
print "pp", pp
ppp = permute(seed,p,1)
print "ppp", ppp
assert ppp==a

print split(permute(seed,range(1,n),0),k)
print permute_global(seed,n,m,2,0)
print split(permute(seed,range(1,n),1),k)
print permute_global(seed,n,m,2,1)
print permute(seed,permute(seed,range(1,n),0),1)
