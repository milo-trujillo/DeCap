# DeCap

*Decapitate PCAP files, figure out what's inside!*

I had to read several large and messy packet capture files, so it seemed like a good time to learn [Scapy](http://www.secdev.org/projects/scapy) and write some code to help. 

Right now the codebase is poorly documented and not meant for other people to use, but some day it might be neat!

## Usage

DeCap is provided as both a library and a few client scripts.

### Libraries

| Module   | Purpose |
| -------- | ------- |
| dns.py   | Parses DNS packets, returning counts, domain names, and full responses |
| stats.py | Returns statistical data about number of hosts, entropy of TTL values, types of packets | 

### Clients

| Script        | Purpose |
| ------------- | ------------------------------------- |
| overview.py   | Prints high-level data about the pcap |
| extractDNS.py | Prints all DNS responses in detail |
