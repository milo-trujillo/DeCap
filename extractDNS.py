#!/usr/bin/env python2
from scapy.all import *
import dns
import sys


def printDNS(filename):
	packets = rdpcap(filename)
	print "Server,Domain,Response"
	for entry in dns.getFullResponses(packets):
		print entry['server'] + "," + entry['domain'] + "," + entry['record']

if( len(sys.argv) != 2 ):
	print "USAGE: " + sys.argv[0] + " <pcap>"
	sys.exit(1)
printDNS(sys.argv[1])
