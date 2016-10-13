from scapy.all import *

def getRequests(packets):
	domains = []
	for p in packets:
		if( DNS in p and p.qdcount > 0 and isinstance(p.qd, DNSQR) ):
			domains += [p.qd.qname]
	return domains

def getRecords(packets):
	domains = []
	for p in packets:
		if( DNS in p and p.ancount > 0 and isinstance(p.an, DNSRR) ):
			domains += [p.an.rdata]
	return domains

def getFullResponses(packets):
	responses = []
	for p in packets:
		if( DNS in p and p.ancount > 0 and isinstance(p.an, DNSRR) ):
			response = {}
			response['server'] = p[1].src
			response['domain'] = p.qd.qname
			response['record'] = p.an.rdata
			responses += [response]
	return responses
