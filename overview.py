#!/usr/bin/env python2
from scapy.all import *
import stats
import dns
import sys


def printStats(filename):
	packets = rdpcap(filename)
	s = stats.getPacketTypeCounts(packets)
	print "TCP packets:   " + str(s['tcp'])
	print "UDP packets:   " + str(s['udp'])
	print "ICMP packets:  " + str(s['icmp'])
	print "Other packets: " + str(s['other'])
	print "TTL entropy:   " + str(stats.getTTYEntropy(packets))
	print "Sources:       " + str(len(stats.getSources(packets)))
	print "Destinations:  " + str(len(stats.getDestinations(packets)))
	print "DNS Lookups:   " + str(len(dns.getRequests(packets)))
	print "DNS Records:   " + str(len(dns.getRecords(packets)))

	print ""
	print "DNS Lookup List"
	print "==============="
	for entry in dns.getRequests(packets):
		print " - " + entry

	print ""	
	print "DNS Response List"
	print "==============="
	for entry in dns.getRecords(packets):
		print " - " + entry

if( len(sys.argv) != 2 ):
	print "USAGE: " + sys.argv[0] + " <pcap>"
	sys.exit(1)
printStats(sys.argv[1])
