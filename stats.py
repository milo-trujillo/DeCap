import math
from scapy.all import *
from collections import Counter

# Returns counts for (tcp, udp, icmp, other)
def getPacketTypeCounts(packets):
	counts = Counter()
	for p in packets:
		if( TCP in p ):
			counts['tcp'] += 1
		elif( UDP in p ):
			counts['udp'] += 1
		elif( ICMP in p ):
			counts['icmp'] += 1
		else:
			counts['other'] += 1
	return counts

def _entropy(data):
	counts = Counter()
	for d in data:
		counts[d] += 1
	probs = [float(c) / len(data) for c in counts.values()]
	ent = 0
	for p in probs:
		if (p > 0.):
			ent -= p * math.log(p, math.exp(1))
	return ent

def getDestinations(packets):
	hosts = Counter()
	for p in packets:
		if IP in p:
			hosts[p[1].dst] += 1
	return hosts	

def getSources(packets):
	hosts = Counter()
	for p in packets:
		if IP in p:
			hosts[p[1].src] += 1
	return hosts	

def getTTYEntropy(packets):
	ttls = []
	for p in packets:
		try:
			ttls += [p[0].ttl]
		except AttributeError:
			ttls
	return _entropy(ttls)
