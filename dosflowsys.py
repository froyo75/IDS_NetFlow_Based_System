#!/usr/bin/python

##########################################################################################
##                                                                         				##
## dosflowsys.py --- NetFlow Based System For Detecting DoS and DDoS Attacks ---        ##
##   																					##
##     Copyright (C) 2012 : Froyo												        ##
##                                                								        ##
##     This program is free software; you can redistribute it and/or modify it          ##
##   under the terms of the GNU General Public License version 2 as                     ##
##   published by the Free Software Foundation.                                         ##
##                                                                         			  	##
##   This program is distributed in the hope that it will be useful, but     			##
##   WITHOUT ANY WARRANTY; without even the implied warranty of              			##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       			##
##   General Public License for more details.                                			##
##                                                                         				##
##########################################################################################

import sys, os, commands
import threading
from sets import Set
from urllib import urlopen
from scapy.all import *
import Queue
import datetime, time, random
import fcntl, struct

MIN_THRESHOLD_TCP_DoS = 50 # Minimum Acceptable Threshold Value (percent) for the Number of TCP DoS/DDoS Attacks
MAX_THRESHOLD_TCP_DoS = 100 # Maximum Acceptable Threshold Value (percent) for the Number of TCP DoS/DDoS Attacks
MIN_THRESHOLD_UDP_DoS = 50 # Minimum Acceptable Threshold Value (percent) for the Number of UDP DoS/DDoS Attacks
MAX_THRESHOLD_UDP_DoS = 100 # Maximum Acceptable Threshold Value (percent) for the Number of UDP DoS/DDoS Attacks
MIN_THRESHOLD_ICMP_DoS = 50 # Minimum Acceptable Threshold Value (percent) for the Number of ICMP DoS/DDoS Attacks
MAX_THRESHOLD_ICMP_DoS = 100 # Maximum Acceptable Threshold Value (percent) for the Number of ICMP DoS/DDoS Attacks
MAX_LB = 15 # Maximum Acceptable Threshold Value for the Number of TCP packets with the "SYN" flags set on Destination port 139/113/135 (Land-Blat Attacks) 
MAX_ACK_PUSH = 15 # Maximum Acceptable Threshold Value for the Number of TCP packets with the "ACK + PUSH" flags set
MAX_TCP_PORT_SCAN = 35 # Maximum Acceptable Threshold Value for the number of TCP Port Scans
MAX_FIN = 35 # Maximum Acceptable Threshold Value for the Number of TCP packets with the "FIN" flag set
MAX_RST = 35 # Maximum Acceptable Threshold Value for the Number of TCP packets with the "RESET" flag set
MAX_PUSH_URG = 35 # Maximum Acceptable Threshold Value for the Number of TCP packets with the "PUSH + URGENT" flags set
MAX_URG = 35 # Maximum Acceptable Threshold Value for the Number of TCP packets with the "URG" flag set (WinNuke Attacks) 
MAX_SYN_FLOOD = 150 # Maximum Acceptable Threshold Value for the Number of TCP packets with the "SYN" flags set
MAX_UDP_FLOOD = 150 # Maximum Acceptable Threshold Value for the Number of UDP packets
MAX_UDP_SCAN = 35 # Maximum Acceptable Threshold Value for the number of UDP Port Scans
MAX_ICMP_ECHO = 150 # Maximum Acceptable Threshold Value for the Number of ICMP "Echo" packets
MAX_ICMP_ECHO_REPLY = 100 # Maximum Acceptable Threshold Value for the Number of ICMP "Echo-Reply" packets
MAX_ICMP_TIME_EXCEEDED = 35 # Maximum Acceptable Threshold Value for the Number of ICMP "Time Exceeded" messages
MAX_ICMP_DEST_UNREACH = 35 # Maximum Acceptable Threshold Value for the Number of ICMP "Destination Unreachable" messages
MAX_ICMP_REDIRECT = 15 # Maximum Acceptable Threshold Value for the Number of ICMP "Redirect" messages
IP_SPOOFING = False # Check IP Address spoofing
GEO_TRACKING = False # Check IP Address location
SERVERS_CONFIG_PATH = 'servers' # Directory which contains all configuration file of servers for DDOS detection
MTU = 1500 # Max MTU per-packet
QSIZE = 0 # Queue size (0 => unlimited Queue Size)
DELAY = 0.1 # Timeout blocking until the internal flag is true
INTERVAL = 1.0 # Window update refresh delay
IFACE = 'tap0' # Sniffing local interface
FILTER = 'src host 192.168.2.254 and port 2055' # Berkeley Packet Filter
IP_SYS_FLOW = '192.168.2.1' # IP address of the NetFlow collector
TIMEOUT = None # Timeout for sniffing
queue = Queue.Queue(QSIZE) # Packet Buffer
threads = [] # Threads list
dicservthreadindex = {} # Server Thread Index Dictionary

#Configuration / Parameters Dictionary
dicparamsconf = { "PORT_DST" : ["PortDstList", "int"],
		  "MAX_TCP_CLIENTS" : ["maxTCPClients", "int"],
		  "MAX_LATENCY" : ["maxLatency", "int"],
		  "MAX_SYN_BACKLOG" : ["maxSynBacklog", "int"] }

#ICMP Type/Code Destination Port defined by Netflow Dictionary
dicicmpdef = {   0 : "Echo Reply",
	       768 : "Net Unreachable",
	       769 : "Host Unreachable",
	       770 : "Protocol Unreachable",
	       771 : "Port Unreachable",
	       772 : "Fragmentation Needed But DF Set",
	       773 : "Source Route Failed",
	       774 : "Destination Network Unknown",
	       775 : "Destination Host Unknown",
	       776 : "Source Host Isolated",
	       777 : "Communication with Destination  Network is Admin Prohibited",
	       778 : "Communication with Destination  Host is Admin Prohibited",
	       779 : "Destination Network Unreachable for Type fo Service",
	       780 : "Destination Host Unreachable for Type of Service",
	       781 : "Communication Administratively Prohibited",
	       782 : "Host Precedence Violation",
	       783 : "Precedence cutoff in effect",
	       1280 : "Redirect datagrams for the Network",
	       1281 : "Redirect datagrams for the Host",
	       1282 : "Redirect datagrams for the Type of Service and Network",
	       1283 : "Redirect datagrams for the Type of Service and Host",
	       2816 : "Time To Live Exceeded in Transit",
	       2817 : "Fragment Reassembly Time Exceeded",
	       2048 : "Echo" }

#Field Type Definitions Dictionary
dicftdef = {    1 : "IN_BYTES",
                2 : "IN_PKTS",
                3 : "FLOWS",
                4 : "PROTOCOL",
                5 : "SRC_TOS",
                6 : "TCP_FLAGS",
                7 : "L4_SRC_PORT",
                8 : "IPV4_SRC_ADDR",
                9 : "SRC_MASK",
                10 : "INPUT_SNMP",
                11 : "L4_DST_PORT",
                12 : "IPV4_DST_ADDR",
                13 : "DST_MASK",
                14 : "OUTPUT_SNMP",
                15 : "IPV4_NEXT_HOP",
                16 : "SRC_AS",
                17 : "DST_AS",
                18 : "BGP_IPV4_NEXT_HOP",
                19 : "MUL_DST_PKTS",
                20 : "MUL_DST_BYTES",
                21 : "LAST_SWITCHED",
                22 : "FIRST_SWITCHED",
                23 : "OUT_BYTES",
                24 : "OUT_PKTS",
                25 : "MIN_PKT_LNGTH",
                26 : "MAX_PKT_LNGTH",
                27 : "IPV6_SRC_ADDR",
                28 : "IPV6_DST_ADDR",
                29 : "IPV6_SRC_MASK",
                30 : "IPV6_DST_MASK",
                31 : "IPV6_FLOW_LABEL",
		32 : "ICMP_TYPE",
                33 : "MUL_IGMP_TYPE",
                34 : "SAMPLING_INTERVAL",
                35 : "SAMPLING_ALGORITHM",
                36 : "FLOW_ACTIVE_TIMEOUT",
                37 : "FLOW_INACTIVE_TIMEOUT",
                38 : "ENGINE_TYPE",
                39 : "ENGINE_ID",
                40 : "TOTAL_BYTES_EXP",
                41 : "TOTAL_PKTS_EXP",
                42 : "TOTAL_FLOWS_EXP",
                43 : "*Vendor Proprietary*",
                44 : "IPV4_SRC_PREFIX",
                45 : "IPV4_DST_PREFIX",
                46 : "MPLS_TOP_LABEL_TYPE",
                47 : "MPLS_TOP_LABEL_IP_ADDR",
                48 : "FLOW_SAMPLER_ID",
                49 : "FLOW_SAMPLER_MODE",
                50 : "FLOW_SAMPLER_RANDOM_INTERVAL",
                51 : "FLOW_CLASS",
		52 : "MIN_TTL",
                53 : "MAX_TTL",
                54 : "IPV4_IDENT",
                55 : "DST_TOS",
                56 : "IN_SRC_MAC",
                57 : "OUT_DST_MAC",
                58 : "SRC_VLAN",
                59 : "DST_VLAN",
                60 : "IP_PROTOCOL_VERSION",
                61 : "DIRECTION",
                62 : "IPV6_NEXT_HOP",
                63 : "BGP_IPV6_NEXT_HOP",
                64 : "IPV6_OPTION_HEADERS",
                65 : "*Vendor Proprietary*",
                66 : "*Vendor Proprietary*",
                67 : "*Vendor Proprietary*",
                68 : "*Vendor Proprietary*",
                69 : "*Vendor Proprietary*",
                70 : "MPLS_LABEL_1",
                71 : "MPLS_LABEL_2",
		72 : "MPLS_LABEL_3",
                73 : "MPLS_LABEL_4",
                74 : "MPLS_LABEL_5",
                75 : "MPLS_LABEL_6",
                76 : "MPLS_LABEL_7",
                77 : "MPLS_LABEL_8",
                78 : "MPLS_LABEL_9",
                79 : "MPLS_LABEL_10",
                80 : "IN_DST_MAC",
                81 : "OUT_SRC_MAC",
                82 : "IF_NAME",
                83 : "IF_DESC",
                84 : "SAMPLER_NAME",
                85 : "IN_PERMANENT_BYTES",
                86 : "IN_PERMANENT_PKTS",
                87 : "*Vendor Proprietary*",
                88 : "FRAGMENT_OFFSET",
                89 : "FORWARDING_STATUS",
                90 : "MPLS_PAL_RD",
                91 : "MPLS_PREFIX_LEN",
		92 : "SRC_TRAFFIC_INDEX",
                93 : "DST_TRAFFIC_INDEX",
                94 : "APPLICATION DESCRIPTION",
                95 : "APPLICATION TAG",
                96 : "APPLICATION NAME",
                97 : "*Vendor Proprietary*",
                98 : "PostipDiffServCodePoint",
                99 : "Replication_Factor",
                100 : "DEPRECATED",
                101 : "*Vendor Proprietary*",
                102 : "layer2packetSectionOffset",
                103 : "layer2packetSectionSize",
                104 : "layer2packetSectionData" }

#Scope Field Type Dictionary
dicsftype = {1:"System",2:"Line Card",3:"Cache",4:"Template"}

#List Of The Saved Templates
tempList = []

#Template Class
class Template:
        def __init__(self, templateID):
                self.id = templateID
                self.length = 0
                self.typeList = []
                self.lengthList = []

        #Store the current Options Template in used
        def save(self, template):
                i = 0
                nbRecords = len(template.Records)
                if nbRecords > 0:
                        for i in range(nbRecords):
                                type = template.Records[i].Type
                                length = template.Records[i].Length
                                self.typeList.append(type)
                                self.lengthList.append(length)
                                self.length += length
                pass

#Options Template Class
class OptionsTemplate:
        def __init__(self, templateID, ScopeFieldType):
                self.id = templateID
                self.ScopeFieldType = dicsftype[ScopeFieldType]
                self.length = 0
                self.typeList = []
                self.lengthList = []

        #Store the current Options Template in used
        def save(self, optionstemplate):
                i = 0
                nbOptionsRecords = len(optionstemplate.OptionsRecords)
                if nbOptionsRecords > 0:
                        for i in range(nbOptionsRecords):
                                type = optionstemplate.OptionsRecords[i].OptionFieldType
                                length = optionstemplate.OptionsRecords[i].OptionFieldLength
                                self.typeList.append(type)
                                self.lengthList.append(length)
                                self.length += length
                pass

#Get The IP Address associated with a network interface (Linux only)
def get_ip_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

#Check IP Address location
def checkIPLocation(IPsrc):
	url = 'http://freegeoip.net/json/'
	country = 'None'
	geoip = url + IPsrc
	try:
		GeoData = eval(urlopen(geoip).read())
		country = GeoData['country_code']
	except:
		print 'URL: Error: Connection !'
	
	return country

#Check IP Address Spoofing
def checkIPSpoofing(IPsrc):
	vb = 0
	timeout = 0.0005
	spoofed = 1
	icmp_ans = sr1(IP(dst=IPServ) / ICMP(), verbose = vb, timeout = timeout)
	if icmp_ans and len(icmp_ans) > 0:
		spoofed = 0
	else:
		spoofed = 1
	return spoofed

#Check Network Latency over time
def checkLatency(PortDstList, IPServ):
	vb = 0
	rt = -1
	timeout = 0.2
	for Portdst in PortDstList:
		startime = time.time()
		tcp_ans = sr1(IP(dst=IPServ) / TCP(dport=Portdst,flags="S"), verbose = vb, timeout = timeout)
		endtime = time.time()
		if tcp_ans and len(tcp_ans) > 0:
			break
	if tcp_ans and len(tcp_ans) > 0:
		rt = int(round((endtime - startime) * 1000))
	elif tcp_ans is None or len(tcp_ans) == 0:
		startime = time.time()
		udp_ans = sr1(IP(dst=IPServ) / UDP(dport=0), verbose = vb, timeout = timeout)
		endtime = time.time()
		if udp_ans and len(udp_ans) > 0:
			rt = int(round((endtime - startime) * 1000))
		else:
			startime = time.time()
			icmp_ans = sr1(IP(dst=IPServ) / ICMP(), verbose = vb, timeout = timeout)
			endtime = time.time()
			if icmp_ans and len(icmp_ans) > 0:
				rt = int(round((endtime - startime) * 1000))
	return rt

#Flow Class
class Flow:
	def __init__(self, IPsrc, IPdst, Portsrc, Portdst, Protocol, TCPFlag, Country, IPSpoofing, Bytes, Pkts, StartTime, EndTime):
		self.IPsrc = IPsrc
		self.IPdst = IPdst
		self.Portsrc = Portsrc
		self.Portdst = Portdst
		self.Protocol = Protocol
		self.TCPFlag = TCPFlag
		self.Country = Country
		self.IPSpoofing = IPSpoofing
		self.Bytes = Bytes
		self.Pkts = Pkts
		self.StartTime = StartTime
		self.EndTime = EndTime

#Process configuration files for servers & Create threads for each server in order to parse each flows according to the destination IP address
def confServParser():
	#Checking if the directory exists or not and if empty
	if os.path.exists(SERVERS_CONFIG_PATH) and len(os.listdir(SERVERS_CONFIG_PATH)) > 0:
		for configFile in os.listdir(SERVERS_CONFIG_PATH):
			#if os.path.isfile(configFile):
			filePath = SERVERS_CONFIG_PATH + "/" + configFile
			#Checking if the configuration file is empty
			if os.path.getsize(filePath) > 0:
				#Opening a file object for reading and parsing each line and strings
				with open(filePath, "r") as f:
					IPdst = f.name.split("/")[1]
					#Create Thread
					confserv = ConfigServ(IPdst)
					#Parsing each line and get the value of each parameter
					for line in f:
						if line.find("=") > 0:
							error = 0
							paramList = line.split("=")
							param = paramList[0].strip()
							#Checking if parameter exists in Parameters Dictionary
							if dicparamsconf.has_key(param):
								#Getting String Attribute
								str_attr = dicparamsconf.get(param)[0]
								#Getting Type Attribute
								type_attr = dicparamsconf.get(param)[1]								
								#Searching if each line contains comma character ',' otherwise sets the attribute
								if line.find(",") > 0:
									#Remove any special characters from string line such as spaces or new lines.
									valuesList = paramList[1].rstrip("\n").split(",")
									i = 0
									for i in range(len(valuesList)):
										value = valuesList[i].strip()
										if value != "" and value != None and value != 0:
											#Setting Type Attribute
											if type_attr == "str":
												value = str(value).upper()
											else:
												value = int(value)
											attr = getattr(confserv, str_attr)
											if type(attr) == type(Set()):
												attr.add(value)
											else:
												error = 1
												print "Parse error: syntax error !!!"
												break
										else:
											pass
								else:
									value = paramList[1].strip().rstrip("\n")
									if value != "" and value != None and value != 0:
										if type_attr == "str":
											value = str(value).upper()
										else:
											value = int(value)
										attr = getattr(confserv, str_attr)
										if type(attr) == type(Set()):
											attr.add(value)
										else:
											setattr(confserv, str_attr, value)
									else:
										pass
						else:
							error = 1
							print "Parse error: syntax error !!!"
							break
			
					if error == 0:
						try:
							#Start threads
	                                      		confserv.start()
							#Add server thread index relating to the thread list into dictionary
							dicservthreadindex[IPdst] = len(threads)
							#Save Thread Index
							confserv.index = len(threads)
							#Add threads to thread list
							threads.append(confserv)
						except:
							print "Error: unable to start thread"
					
	#else:
	#	print "Error > No such file or directory !!!"

#Get CPU/MEM Usage
def get_cpumem(pid):
	d = [i for i in commands.getoutput("ps aux").split("\n") if i.split()[1] == str(pid)]
	return (pid, float(d[0].split()[2]), float(d[0].split()[3])) if d else None 

#Check if the template id already exists
def checkTemp(id):
	t = 0
	match = 0
	for t in range(len(tempList)):
		if tempList[t].id == id:
			match = 1
			return t
		pass
	if match == 0:
		return -1

#Create the current Template in used
def createTemp(templates):
	i = 0
	nbTemp = len(templates)
	if nbTemp > 0:
		for i in range(nbTemp):
			id = templates[i].TemplateID
			if checkTemp(id) == -1 and id > 255:
				Temp = Template(id)
				tempList.append(Temp)
				Temp.save(templates[i])
			pass
	pass

#Create the current Options Template in used
def createOptionsTemp(optionstemplates):
	i = 0
	nbOptionsTemp = len(optionstemplates)
	if nbOptionsTemp > 0:
		for i in range(nbOptionsTemp):
			id = optionstemplates[i].TemplateID
			if checkTemp(id) == -1 and id > 255:
				ScopeFieldType = optionstemplates[i].OptionsScopeRecords[0].ScopeFieldType
				OptionsTemp = OptionsTemplate(id, ScopeFieldType)
				tempList.append(OptionsTemp)
				OptionsTemp.save(optionstemplates[i])
			pass
	pass

#Process Flows to produce the Hashtable
def processFlow(hashtable, flow, type):
	if type == 0:
		IPsrc = flow.IPsrc
		Portdst = flow.Portdst
	else:
		IPsrc = flow.IPdst
		Portdst = flow.Portsrc

	if hashtable.has_key(IPsrc):
		hashtable[IPsrc][0] += 1
	else:
		hashtable.update({IPsrc: [ 1, flow.IPSpoofing, flow.Country, {} ] } )

	if hashtable[IPsrc][3].has_key(Portdst):
		hashtable[IPsrc][3][Portdst][0] += 1
	else:
		hashtable[IPsrc][3].update( {Portdst: [ 1, {} ] } )

	if flow.Protocol == "TCP":
		if hashtable[IPsrc][3][Portdst][1].has_key(flow.TCPFlag):
			hashtable[IPsrc][3][Portdst][1][flow.TCPFlag][0] += 1
			hashtable[IPsrc][3][Portdst][1][flow.TCPFlag][1].update( { flow.StartTime: [flow.EndTime, flow.Bytes, flow.Pkts] } )		
		else:
			hashtable[IPsrc][3][Portdst][1].update( { flow.TCPFlag: [ 1, {} ] } )
			hashtable[IPsrc][3][Portdst][1][flow.TCPFlag][1].update( { flow.StartTime: [flow.EndTime, flow.Bytes, flow.Pkts] } )
		
	elif flow.Protocol == "UDP" or flow.Protocol == "ICMP":
		hashtable[IPsrc][3][Portdst][1].update( { flow.StartTime: [flow.EndTime, flow.Bytes, flow.Pkts] } )

#Dispatch Flows
def flowDispatcher(flow):
	hashtable = {}
	if dicservthreadindex.has_key(flow.IPdst) and flow.IPdst != IP_SYS_FLOW:
		#Get index from "dicservthreadindex" dictionary 
		index = dicservthreadindex.get(flow.IPdst)	
		type = 0
		if flow.Protocol == "TCP":
			hashtable = threads[index].TCPflowList_IPsrc
		elif flow.Protocol == "UDP":
			hashtable = threads[index].UDPflowList_IPsrc
		elif flow.Protocol == "ICMP":
			hashtable = threads[index].ICMPflowList_IPsrc
		processFlow(hashtable, flow, type)
		
	elif dicservthreadindex.has_key(flow.IPsrc) and flow.IPsrc != IP_SYS_FLOW:
		index = dicservthreadindex.get(flow.IPsrc)
		type = 1
		if flow.Protocol == "TCP":
			hashtable = threads[index].TCPflowList_IPServ
		elif flow.Protocol == "ICMP":
			hashtable = threads[index].ICMPflowList_IPServ 
		processFlow(hashtable, flow, type)

#Get & Store Data Records From Flows
def getData(tempIndex, payload):
	i = 0
	j = 0
	k = 0
	EndTime = 0
	StartTime = 0
	Bytes = 0
	Pkts = 0
	IPsrc = ''
	IPdst = ''
	Protocol = ''
	Portsrc = 0
	Portdst = 0
	TCPFlag = ''
	for i in range(len(tempList[tempIndex].typeList)):
		ClassTypeStr = dicftdef.get(tempList[tempIndex].typeList[i])
		k = tempList[tempIndex].lengthList[i] + j
		data = payload[j:k]
		if ClassTypeStr != "*Vendor Proprietary*":
			try:
				ObjType = eval(ClassTypeStr + "(data)")
				Record = getattr(ObjType, ClassTypeStr)
				#ObjType.show()
				#Store Data Record From Flow
				if ClassTypeStr == "LAST_SWITCHED":
					EndTime = int(Record)	
				if ClassTypeStr == "FIRST_SWITCHED":
					StartTime = int(Record)
				if ClassTypeStr == "IN_BYTES":
					Bytes = int(Record)
				if ClassTypeStr == "IN_PKTS":
					Pkts = int(Record)
				if ClassTypeStr == "IPV4_SRC_ADDR":
					IPsrc = str(Record)
				if ClassTypeStr == "IPV4_DST_ADDR":
					IPdst = str(Record)
				if ClassTypeStr == "PROTOCOL":
					Protocol = ObjType.sprintf("%PROTOCOL%").upper()
				if ClassTypeStr == "L4_SRC_PORT":
					Portsrc = int(Record) 
				if ClassTypeStr == "L4_DST_PORT":
					Portdst = int(Record)
				if ClassTypeStr == "TCP_FLAGS":
					TCPFlag = ObjType.sprintf("%TCP_FLAGS%").upper()
			except:
				pass
			j = k
		pass
	#Check for IP Spoofing
	if IP_SPOOFING == True:
		if checkIPSpoofing(IPsrc) == 1:
			IPSpoofing = 'Yes'
		else:
			IPSpoofing = 'No' 
	else:
		IPSpoofing = None
	#Check IP Address location
	if GEO_TRACKING == True:
		Country = checkIPLocation(IPsrc)
	else:
		Country = "None"
	#Create a Flow Object
	flow = Flow(IPsrc, IPdst, Portsrc, Portdst, Protocol, TCPFlag, Country, IPSpoofing, Bytes, Pkts, StartTime, EndTime)
	flowDispatcher(flow)

#Get Flows from FlowSets
def getFlows(id, FlowSet):
	i = 0
	k = 0
	tempIndex = checkTemp(id)
	if tempIndex >= 0:
		tempLength = tempList[tempIndex].length
		j = tempLength
		length = FlowSet.Length
		nbFlows = length / tempLength
		for i in range(nbFlows):
			payload = FlowSet.Datas[0].load[k:j]
			getData(tempIndex, payload)
			k = j
			j += tempLength
	pass

#Dissect NetFlow Packets Version 9
def dissect(Packet):
	j = 0
	#print "Packet => %d" %(i+1)
	try:
		nbFlowSet = len(Packet[Ether][IP][UDP][Header].FlowsetList)
		assert nbFlowSet > 0
        except ValueError:
        	print("No such variable FlowsetList !")
        except AssertionError:
       		print("No FlowSet found !!!")
	else:
		for j in range(nbFlowSet):
			#Get FlowSet ID
                    	FlowSetID = Packet[Ether][IP][UDP][Header].FlowsetList[j].FlowSetID
			#Template
          		if FlowSetID == 0:
         			templates = Packet[Ether][IP][UDP][Header].FlowsetList[j].Templates
            			createTemp(templates)
				#print "Got Template !"
			#Options Template
                	if FlowSetID == 1:
             			optionstemplates = Packet[Ether][IP][UDP][Header].FlowsetList[j].OptionsTemplates
     				createOptionsTemp(optionstemplates)
				#print "Got Options Template !"
			#Data Records
           		if FlowSetID > 255:
                		FlowSet = Packet[Ether][IP][UDP][Header].FlowsetList[j]
              			getFlows(FlowSetID, FlowSet)
				#print "Got Data Records"

#Parser Threading Class
class Parser(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.__queue = queue
        	self._stopevent = threading.Event()

    	def run(self):
		try:
			print "Start Parsing..."
			while not self._stopevent.isSet():
                		packet = self.__queue.get()
                		if packet is not None:
					dissect(packet)
			#self._stopevent.wait(DELAY)
			print "Stop Parsing..."		
		except KeyboardInterrupt:
			exit_p()

	def stop(self):
		self._stopevent.set()

#Sniffer Threading Class
class Sniffer(threading.Thread):
	def __init__(self):
        	threading.Thread.__init__(self)
		self._stopevent = threading.Event()		

    	def run(self):
		try:
			print "Start Sniffing..."        	
			stoptime = 0
			remain = None
			if TIMEOUT is not None:
        			stoptime = time.time()+TIMEOUT
			while not self._stopevent.isSet():
                		s = conf.L2socket(filter=FILTER, iface=IFACE)
				if TIMEOUT is not None:
					remain = stoptime-time.time()
                			if remain <= 0:
                    				break
				sel = select([s],[],[],remain)
				if s in sel[0]:			
					packet = s.recv(MTU)
                			if packet is None:
						break
				#Add the packet to the queue
                		if queue.full():
                			print "Queue is full...waiting for a free slot available"
				queue.put(packet)
				#self._stopevent.wait(DELAY)
			s.close()
			print "Stop Sniffing..."
		except KeyboardInterrupt:
			exit_p()

	def stop(self):
		self._stopevent.set()

#Window Live Stats Threading Class
class WLS(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self._stopevent = threading.Event()
		self.pid = os.getpid()
		self.AlertsList = {}
		self.Portdst = ''
		self.StartTime = ''
		self.EndTime = ''
		self.title = ''
		self.now = ''
		self.datetime = ''
		self.usage = ''
		self.alert = ''
		self.x = 0

	def run(self):
		try:
			#print "Start WLS..."
			while not self._stopevent.isSet():
				self.x = get_cpumem(self.pid)
				if not self.x:
					print("no such process")
					exit(1)
				self.title = "[\tDDoS NetFlow System\t]"
				self.now = datetime.datetime.now()
				self.datetime = self.now.strftime("\t%Y-%m-%d %I:%M:%S %p %Z")
				self.usage = "\tPID\t%CPU\t%MEM\t"
				self.alert = "\n|Count|\t|Target IP|\t|Port|\t|Description|\t\t|Flows|\t|Start|\t\t\t|End|\t\t\t|Level|"
				os.system("clear")
				sys.stdout.write("%s\n\n" % self.title)
				sys.stdout.write("DATE:%s\n\n" % self.datetime)
				sys.stdout.write("USAGE:%s\n" % self.usage)
				sys.stdout.write("\r      \t%d\t%.2f\t%.2f\n\n" % self.x)
				sys.stdout.write("ALERTS:\n%s\n\n" % self.alert)
				for IPServ in dicservthreadindex.keys():
					self.AlertsList = threads[dicservthreadindex[IPServ]].AlertsList.copy()
					if len(self.AlertsList) > 0:
						for tag in self.AlertsList.keys():
							if tag == 'XSC' or tag == 'SSC' or tag == 'FSC' or tag == 'NSC' or tag == 'ASC' or tag == 'USC' or tag == 'UFD':
								self.Portdst = 'Any'
								self.StartTime = time.ctime(int(self.AlertsList[tag][4]))
								self.EndTime = time.ctime(int(self.AlertsList[tag][5]))
								sys.stdout.write("%d\t" % self.AlertsList[tag][0])
								sys.stdout.write("%s\t" % IPServ)
								sys.stdout.write("%s\t" % self.Portdst)
								sys.stdout.write("%s " % self.AlertsList[tag][2])
								sys.stdout.write("%d\t" % self.AlertsList[tag][3])
								sys.stdout.write("%s " % self.StartTime)
								sys.stdout.write("%s " % self.EndTime)
								sys.stdout.write("%s \n" % self.AlertsList[tag][6])
							else:
								for Portdst in self.AlertsList[tag][1].keys():
									self.StartTime = time.ctime(int(self.AlertsList[tag][1][Portdst][4]))
									self.EndTime = time.ctime(int(self.AlertsList[tag][1][Portdst][5]))
									sys.stdout.write("%d\t" % self.AlertsList[tag][1][Portdst][0])
									sys.stdout.write("%s\t" % IPServ)
									sys.stdout.write("%d\t" % Portdst)
									sys.stdout.write("%s " % self.AlertsList[tag][1][Portdst][2])
									sys.stdout.write("%d\t" % self.AlertsList[tag][1][Portdst][3])
									sys.stdout.write("%s " % self.StartTime)
									sys.stdout.write("%s " % self.EndTime)
									sys.stdout.write("%s \n" % self.AlertsList[tag][1][Portdst][6])
				sys.stdout.flush()
 				time.sleep(INTERVAL)
                	#self._stopevent.wait(DELAY)
                	#print "Stop WLS..."
		except KeyboardInterrupt:
			exit_p()

        def stop(self):
                self._stopevent.set()

#Remove entry from the hashtable
def removeEntryHashtable(IPsrc, Portdst, flags, hashtable):
	if len(hashtable) > 0:
		if hashtable.has_key(IPsrc):
			if hashtable[IPsrc][3].has_key(Portdst):
				if flags != '':
					if hashtable[IPsrc][3][Portdst][1].has_key(flags):
						del hashtable[IPsrc][3][Portdst][1][flags]
				else:
					del hashtable[IPsrc][3][Portdst]

#Check TCP Flags entry from the hashtable
def checkTCPFlags(IPsrc, Portdst, flags, hashtable):
	count = 0
	if len(hashtable) > 0:
		if hashtable.has_key(IPsrc):
			if hashtable[IPsrc][3].has_key(Portdst):
				if hashtable[IPsrc][3][Portdst][1].has_key(flags):
					count = hashtable[IPsrc][3][Portdst][1][flags][0]
	return count

#Create TCP DoS/DDoS Alerts
def createTCPAlert(Portdst, rate, level, list, nflows, tag, description, StartTime, TOTAL_TCP_PORT_SCAN, TOTAL_CLIENTS, TOTAL_SYN, index):
	if rate in range(MIN_THRESHOLD_TCP_DoS,MAX_THRESHOLD_TCP_DoS):
		level = 'Medium'
	elif rate == MIN_THRESHOLD_TCP_DoS:
		level = 'Low'
	elif rate == MAX_THRESHOLD_TCP_DoS:
		level = 'High'

	if tag == 'XSC' or tag == 'SSC' or tag == 'FSC' or tag == 'NSC' or tag == 'ASC':
		if TOTAL_TCP_PORT_SCAN >= MAX_TCP_PORT_SCAN:
			level = 'Critical TCP PORT SCAN VIOLATIONS'
	elif tag == 'SFD':
		if TOTAL_SYN >= threads[index].maxSynBacklog:
			level = 'Critical SYN Backlog Queue Size'
	elif tag == 'NUKE' or tag == 'APA' or tag == 'PUA' or tag == 'FV' or tag == 'RV':
		if TOTAL_CLIENTS >= threads[index].maxTCPClients:
			level = 'Critical TCP Clients'

	if level != "" and description != '' and len(list) > 0:
		if tag == 'XSC' or tag == 'SSC' or tag == 'FSC' or tag == 'NSC' or tag == 'ASC':
			if threads[index].AlertsList.has_key(tag):
				threads[index].AlertsList[tag][0] += 1
				threads[index].AlertsList[tag][1] = list
				threads[index].AlertsList[tag][3] = nflows
				threads[index].AlertsList[tag][6] = level
				EndTime = time.time()
                		threads[index].AlertsList[tag][5] = EndTime
			else:
				threads[index].AlertsList.update({tag: [1, list, description, nflows, StartTime, StartTime, level] })
		else:
			if threads[index].AlertsList.has_key(tag):
				threads[index].AlertsList[tag][0] += 1
				if threads[index].AlertsList[tag][1].has_key(Portdst):
					threads[index].AlertsList[tag][1][Portdst][0] += 1
					threads[index].AlertsList[tag][1][Portdst][1] = list
					threads[index].AlertsList[tag][1][Portdst][3] = nflows
					threads[index].AlertsList[tag][1][Portdst][6] = level
					EndTime = time.time()
					threads[index].AlertsList[tag][1][Portdst][5] = EndTime
				else:
					threads[index].AlertsList[tag][1].update({Portdst: [1, list, description, nflows, StartTime, StartTime, level] })
			else:
				threads[index].AlertsList.update({tag: [1, { Portdst: [ 1, list, description, nflows, StartTime, StartTime, level] } ] })	

#Check TCP Dos/DDos Attacks
class TCPDoS(threading.Thread):
	def __init__(self, index):
		threading.Thread.__init__(self)
		self._stopevent = threading.Event()
		self.index = index
		self.hashtable_IPsrc = {}
		self.hashtable_IPServ = {}
		self.TOTAL_TCP_PORT_SCAN = 0
		self.TOTAL_XMAS_SCAN = 0
		self.TOTAL_SYN_SCAN = 0
		self.TOTAL_FIN_SCAN = 0
		self.TOTAL_NULL_SCAN = 0
		self.TOTAL_ACK_SCAN = 0
		self.TOTAL_ACK_PUSH = 0
		self.TOTAL_PUSH_URG = 0
		self.TOTAL_FIN = 0
		self.TOTAL_SYN = 0
		self.TOTAL_RST = 0
		self.TOTAL_URG = 0
		self.TOTAL_LB = 0
		self.TOTAL_CLIENTS = 0
		
		self.XMAS_SCAN_LIST = {}
		self.SYN_SCAN_LIST = {}
		self.FIN_SCAN_LIST = {}
		self.NULL_SCAN_LIST = {}
		self.ACK_SCAN_LIST = {}		
		self.ACK_PUSH_LIST = {}
		self.PUSH_URG_LIST = {}
		self.FIN_LIST = {}
		self.SYN_LIST = {}
		self.RST_LIST = {}
		self.URG_LIST = {}
		self.LB_LIST = {}

		self.StartTime = 0
		self.tag = ''
		self.nflows = 0
		self.count = 0
		self.rate = 0
		self.level = ''
		self.description = ''
		self.list = {}

	def run(self):
		while not self._stopevent.isSet():
			if len(threads[self.index].TCPflowList_IPsrc) > 0:
				self.hashtable_IPsrc = threads[self.index].TCPflowList_IPsrc.copy()
				self.hashtable_IPServ = threads[self.index].TCPflowList_IPServ.copy()
				for IPsrc in self.hashtable_IPsrc.keys():
					for Portdst in self.hashtable_IPsrc[IPsrc][3].keys():
						self.count = 0
						self.rate = 0
						self.level = ''
						self.description = ''
						self.StartTime = 0
						self.nflows = 0
						self.tag = ''
						self.list = {}
						if Portdst not in threads[self.index].PortDstList:
							for flags in self.hashtable_IPsrc[IPsrc][3][Portdst][1].keys():
								if flags == 'FPU' or flags == 'S' or flags == 'F' or flags == '':
									if checkTCPFlags(IPsrc, Portdst, 'RA', self.hashtable_IPServ) != 0:
										if flags == 'FPU':
											self.TOTAL_XMAS_SCAN += 1
											self.TOTAL_TCP_PORT_SCAN += 1
											if self.XMAS_SCAN_LIST.has_key(IPsrc):
												self.XMAS_SCAN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0] 
											else:
												self.XMAS_SCAN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
											self.rate =  int(round((self.TOTAL_XMAS_SCAN*100)/MAX_TCP_PORT_SCAN))
											self.description = 'TCP XMAS PORT SCAN ATTACKS'
											self.list = self.XMAS_SCAN_LIST
											self.nflows = self.TOTAL_XMAS_SCAN
											self.StartTime = time.time()
											self.tag = 'XSC'
										elif flags == 'S':
											self.TOTAL_SYN_SCAN += 1
											self.TOTAL_TCP_PORT_SCAN += 1
											if self.SYN_SCAN_LIST.has_key(IPsrc):
												self.SYN_SCAN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
											else:
												self.SYN_SCAN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
											self.rate =  int(round((self.TOTAL_SYN_SCAN*100)/MAX_TCP_PORT_SCAN))
											self.description = 'TCP SYN PORT SCAN ATTACKS'
											self.list = self.SYN_SCAN_LIST
											self.nflows = self.TOTAL_SYN_SCAN
											self.StartTime = time.time()
											self.tag = 'SSC'
										elif flags == 'F':
											self.TOTAL_FIN_SCAN += 1
											self.TOTAL_TCP_PORT_SCAN += 1
											if self.FIN_SCAN_LIST.has_key(IPsrc):
												self.FIN_SCAN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
											else:
												self.FIN_SCAN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
											self.rate =  int(round((self.TOTAL_FIN_SCAN*100)/MAX_TCP_PORT_SCAN))
											self.description = 'TCP FIN PORT SCAN ATTACKS'
											self.list= self.FIN_SCAN_LIST
											self.nflows = self.TOTAL_FIN_SCAN
											self.StartTime = time.time()
											self.tag = 'FSC'
										elif flags == '':
											self.TOTAL_NULL_SCAN += 1
											self.TOTAL_TCP_PORT_SCAN += 1
											if self.NULL_SCAN_LIST.has_key(IPsrc):
												self.NULL_SCAN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
											else:
												self.NULL_SCAN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
											self.rate =  int(round((self.TOTAL_NULL_SCAN*100)/MAX_TCP_PORT_SCAN))
											self.description = 'TCP NULL PORT SCAN ATTACKS'
											self.list = self.NULL_SCAN_LIST
											self.nflows = self.TOTAL_NULL_SCAN
											self.StartTime = time.time()
											self.tag = 'NSC'
										createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)
										removeEntryHashtable(IPsrc, Portdst, 'RA', threads[self.index].TCPflowList_IPServ)
										removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)
								elif flags == 'A':
									if checkTCPFlags(IPsrc, Portdst, 'R', threads[self.index].TCPflowList_IPServ) != 0:
										self.TOTAL_ACK_SCAN += 1
										self.TOTAL_TCP_PORT_SCAN += 1
										if self.ACK_SCAN_LIST.has_key(IPsrc):
											self.ACK_SCAN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
										else:
											self.ACK_SCAN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})					
										self.rate =  int(round((self.TOTAL_ACK_SCAN*100)/MAX_TCP_PORT_SCAN))
										self.description = 'TCP ACK PORT SCAN ATTACKS'
										self.list = self.ACK_SCAN_LIST
										self.nflows = self.TOTAL_ACK_SCAN
										self.StartTime = time.time()
										self.tag = 'ASC'
										createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)
										removeEntryHashtable(IPsrc, Portdst, 'R', threads[self.index].TCPflowList_IPServ)
										removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)
						elif Portdst == 139 or Portdst == 445:
							for flags in self.hashtable_IPsrc[IPsrc][3][Portdst][1].keys():
								if flags == 'U':
									if checkTCPFlags(IPsrc, Portdst, 'SR', self.hashtable_IPsrc) != 0 and checkTCPFlags(IPsrc, Portdst, 'SA', self.hashtable_IPServ) != 0:
										self.TOTAL_CLIENTS += 1
										self.TOTAL_URG += 1
										removeEntryHashtable(IPsrc, Portdst, 'SA', threads[self.index].TCPflowList_IPServ)
										removeEntryHashtable(IPsrc, Portdst, 'SR', threads[self.index].TCPflowList_IPsrc)
										if self.URG_LIST.has_key(IPsrc):
											self.URG_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
										else:
											self.URG_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
										self.rate =  int(round((self.TOTAL_URG*100)/MAX_URG))
										self.description = 'TCP WINNUKE ATTACKS'
										self.list = self.URG_LIST
										self.nflows = self.TOTAL_URG
										self.StartTime = time.time()
										self.tag = 'NUKE'
										createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)
										removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)
						else:
							for flags in self.hashtable_IPsrc[IPsrc][3][Portdst][1].keys():
								if flags == 'PA':
									if checkTCPFlags(IPsrc, Portdst, 'SR', self.hashtable_IPsrc) != 0 and checkTCPFlags(IPsrc, Portdst, 'SA', self.hashtable_IPServ) != 0:
										self.TOTAL_CLIENTS += 1
										self.TOTAL_ACK_PUSH += 1
										if self.ACK_PUSH_LIST.has_key(IPsrc):
											self.ACK_PUSH_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
										else:
											self.ACK_PUSH_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
										self.rate =  int(round((self.TOTAL_ACK_PUSH*100)/MAX_ACK_PUSH))
										self.description = 'TCP ACK+PUSH ATTACKS'
										self.list = self.ACK_PUSH_LIST
										self.nflows = self.TOTAL_ACK_PUSH  
										self.StartTime = time.time()
										self.tag = 'APA'
										createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)									
										removeEntryHashtable(IPsrc, Portdst, 'SR', threads[self.index].TCPflowList_IPsrc)
										removeEntryHashtable(IPsrc, Portdst, 'SA', threads[self.index].TCPflowList_IPServ)
										removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)
								elif flags == 'PU':
									if checkTCPFlags(IPsrc, Portdst, 'SR', self.hashtable_IPsrc) != 0 and checkTCPFlags(IPsrc, Portdst, 'SA', self.hashtable_IPServ) != 0:		
										self.TOTAL_CLIENTS += 1
										self.TOTAL_PUSH_URG += 1
										if self.PUSH_URG_LIST.has_key(IPsrc):
											self.PUSH_URG_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
										else:
											self.PUSH_URG_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
										self.rate =  int(round((self.TOTAL_PUSH_URG*100)/MAX_PUSH_URG))
										self.description = 'TCP PUSH+URG ATTACKS'
										self.list = self.PUSH_URG_LIST
										self.nflows = self.TOTAL_PUSH_URG
										self.StartTime = time.time()
										self.tag = 'PUA'
										createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)
										removeEntryHashtable(IPsrc, Portdst, 'SR', threads[self.index].TCPflowList_IPsrc)
										removeEntryHashtable(IPsrc, Portdst, 'SA', threads[self.index].TCPflowList_IPServ)
										removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)
								elif flags == 'F':
									if checkTCPFlags(IPsrc, Portdst, 'SR', self.hashtable_IPsrc) != 0 and checkTCPFlags(IPsrc, Portdst, 'SA', self.hashtable_IPServ) != 0:		
										self.TOTAL_CLIENTS += 1	
										self.TOTAL_FIN += 1
										if self.FIN_LIST.has_key(IPsrc):
											self.FIN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
										else:
											self.FIN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
										self.rate =  int(round((self.TOTAL_FIN*100)/MAX_FIN))
										self.description = 'TCP FIN VIOLATIONS'
										self.list = self.FIN_LIST
										self.nflows = self.TOTAL_FIN
										self.StartTime = time.time()
										self.tag = 'FV'
										createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)
										removeEntryHashtable(IPsrc, Portdst, 'SR', threads[self.index].TCPflowList_IPsrc)
										removeEntryHashtable(IPsrc, Portdst, 'SA', threads[self.index].TCPflowList_IPServ)
										removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)
								elif flags == 'R':
									if checkTCPFlags(IPsrc, Portdst, 'SR', self.hashtable_IPsrc) != 0 and checkTCPFlags(IPsrc, Portdst, 'SA', self.hashtable_IPServ) != 0:		
										self.TOTAL_CLIENTS += 1	
										self.TOTAL_RST += 1
										if self.RST_LIST.has_key(IPsrc):
											self.RST_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
										else:
											self.RST_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
										self.rate =  int(round((self.TOTAL_RST*100)/MAX_RST))
										self.description = 'TCP RST VIOLATIONS'
										self.list = self.RST_LIST
										self.nflows = self.TOTAL_RST
										self.StartTime = time.time()
										self.tag = 'RV'
										reateTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)
										removeEntryHashtable(IPsrc, Portdst, 'SR', threads[self.index].TCPflowList_IPsrc)
										removeEntryHashtable(IPsrc, Portdst, 'SA', threads[self.index].TCPflowList_IPServ)
										removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)
								elif flags == 'S':
									self.TOTAL_SYN += 1
									if self.SYN_LIST.has_key(IPsrc):
										self.SYN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0]
									else:
										self.SYN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
									self.rate =  int(round((self.TOTAL_SYN*100)/MAX_SYN_FLOOD))
									self.description = 'TCP SYN FLOODING ATTACKS'
									self.list = self.SYN_LIST
									self.nflows = self.TOTAL_SYN
									self.StartTime = time.time()
									self.tag = 'SFD'
									createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)									
									removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPsrc)

			elif len(threads[self.index].TCPflowList_IPServ) > 0:
				self.hashtable_IPServ = threads[self.index].TCPflowList_IPServ.copy()
				for IPsrc in self.hashtable_IPServ.keys():
					for Portdst in self.hashtable_IPServ[IPsrc][3].keys():
						self.count = 0
						self.rate = 0
						self.level = ''
						self.description = ''
						self.StartTime = 0
						self.nflows = 0
						self.tag = ''
						self.list = {}
						if Portdst == 139 or Portdst == 113 or Portdst == 135:
							for flags in self.hashtable_IPServ[IPsrc][3][Portdst][1].keys():
								if flags == 'S':
									self.TOTAL_LB += 1
									if self.LB_LIST.has_key(IPsrc):
										self.LB_LIST[IPsrc][0] += self.hashtable_IPServ[IPsrc][3][Portdst][1][flags][0]
									else:
										self.LB_LIST.update({IPsrc : [self.hashtable_IPServ[IPsrc][3][Portdst][1][flags][0], self.hashtable_IPServ[IPsrc][1], self.hashtable_IPServ[IPsrc][2]]})
									self.rate =  int(round((self.TOTAL_LB*100)/MAX_LB))
									self.description = 'TCP SYN LAND-BLAT ATTACKS'
									self.list = self.LB_LIST
									self.nflows = self.TOTAL_LB
									self.StartTime = time.time()
									self.tag = 'LBA'
									createTCPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_TCP_PORT_SCAN, self.TOTAL_CLIENTS, self.TOTAL_SYN, self.index)
									removeEntryHashtable(IPsrc, Portdst, flags, threads[self.index].TCPflowList_IPServ)
		#self._stopevent.wait(DELAY)
		#print "Stop Checking TCP Scans..."
	
	def stop(self):
		self._stopevent.set()

#Check ICMP entry from the hashtable
def checkICMP(IPsrc, Portdst, hashtable):
	count = 0
	if len(hashtable) > 0:
		if hashtable.has_key(IPsrc):
			if hashtable[IPsrc][3].has_key(Portdst):
				count = hashtable[IPsrc][3][Portdst][0]
	return count

#Create UDP DoS/DDoS Alerts
def createUDPAlert(rate, level, list, nflows, tag, description, StartTime, TOTAL_UDP_SCAN, index):
	if rate in range(MIN_THRESHOLD_UDP_DoS,MAX_THRESHOLD_UDP_DoS):
		level = 'Medium'
	elif rate == MIN_THRESHOLD_UDP_DoS:
		level = 'Low'
	elif rate >= MAX_THRESHOLD_UDP_DoS:
		level = 'High'
	if tag == 'USC':
		if TOTAL_UDP_SCAN >= MAX_UDP_SCAN:
			level = 'Critical UDP PORT SCAN VIOLATIONS'

	if level != "" and description != '' and len(list) > 0:
		if threads[index].AlertsList.has_key(tag):
			threads[index].AlertsList[tag][0] += 1
			threads[index].AlertsList[tag][1] = list
			threads[index].AlertsList[tag][3] = nflows
			threads[index].AlertsList[tag][6] = level
			EndTime = time.time()
			threads[index].AlertsList[tag][5] = EndTime
		else:
			threads[index].AlertsList.update({tag: [1, list, description, nflows, StartTime, StartTime, level] })		

#Check UDP Dos/DDos Attacks
class UDPDoS(threading.Thread):
	def __init__(self, index):
		threading.Thread.__init__(self)
		self._stopevent = threading.Event()
		self.index = index
		self.hashtable_IPsrc = {}
		self.hashtable_IPServ = {}
		self.TOTAL_UDP_SCAN = 0
		self.TOTAL_UDP = 0

		self.UDP_SCAN_LIST = {}
		self.UDP_LIST = {}		

		self.StartTime = 0
		self.tag = ''
		self.nflows = 0
		self.count = 0
		self.rate = 0
		self.level = ''
		self.description = ''
		self.list = {}

	def run(self):
		while not self._stopevent.isSet():
			if len(threads[self.index].UDPflowList_IPsrc) > 0:
				self.hashtable_IPsrc = threads[self.index].UDPflowList_IPsrc.copy()
				self.hashtable_IPServ = threads[self.index].ICMPflowList_IPServ.copy()
				for IPsrc in self.hashtable_IPsrc.keys():
					for Portdst in self.hashtable_IPsrc[IPsrc][3].keys():
						self.count = 0
						self.rate = 0
						self.level = ''
						self.description = ''
						self.StartTime = 0
						self.nflows = 0
						self.tag = ''
						self.list = {}
						if Portdst not in threads[self.index].PortDstList:
							if checkICMP(IPsrc, 771, self.hashtable_IPServ) != 0:
								self.TOTAL_UDP_SCAN += 1
								removeEntryHashtable(IPsrc, Portdst, '', threads[self.index].ICMPflowList_IPServ)
								if self.UDP_SCAN_LIST.has_key(IPsrc):
									self.UDP_SCAN_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][0]
								else:
									self.UDP_SCAN_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
								self.rate =  int(round((self.TOTAL_UDP_SCAN*100)/MAX_UDP_SCAN))
								self.description = 'UDP SCAN ATTACKS / ' + dicicmpdef[Portdst]
								self.list = self.UDP_SCAN_LIST
								self.nflows = self.TOTAL_UDP_SCAN
								self.StartTime = time.time()
								self.tag = 'USC'
								createUDPAlert(self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_UDP_SCAN, self.index)
								removeEntryHashtable(IPsrc, Portdst, '', threads[self.index].UDPflowList_IPsrc)
							else:
								self.TOTAL_UDP += 1
								if self.UDP_LIST.has_key(IPsrc):
									self.UDP_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][0]
								else:
									self.UDP_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
								self.rate =  int(round((self.TOTAL_UDP*100)/MAX_UDP_FLOOD))
								self.description = 'UDP FLOODING ATTACKS'
								self.list = self.UDP_LIST
								self.nflows = self.TOTAL_UDP
								self.StartTime = time.time()
								self.tag = 'UFD'
								createUDPAlert(self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.TOTAL_UDP_SCAN, self.index)
								removeEntryHashtable(IPsrc, Portdst, '', threads[self.index].UDPflowList_IPsrc)
		#self._stopevent.wait(DELAY)
		#print "Stop Checking UDP Scans..."
	
	def stop(self):
		self._stopevent.set()

#Create ICMP DoS/DDoS Alerts
def createICMPAlert(Portdst, rate, level, list, nflows, tag, description, StartTime, index):
	if rate in range(MIN_THRESHOLD_ICMP_DoS,MAX_THRESHOLD_ICMP_DoS):
		level = 'Medium'
	elif rate == MIN_THRESHOLD_ICMP_DoS:
		level = 'Low'
	elif rate >= MAX_THRESHOLD_ICMP_DoS:
		level = 'High'

	if level != "" and description != '' and len(list) > 0:
		if threads[index].AlertsList.has_key(tag):
			threads[index].AlertsList[tag][0] += 1
			if threads[index].AlertsList[tag][1].has_key(Portdst):
        			threads[index].AlertsList[tag][1][Portdst][0] += 1
				threads[index].AlertsList[tag][1][Portdst][1] = list
				threads[index].AlertsList[tag][1][Portdst][3] = nflows
				threads[index].AlertsList[tag][1][Portdst][6] = level
				EndTime = time.time()
				threads[index].AlertsList[tag][1][Portdst][5] = EndTime
			else:
				threads[index].AlertsList[tag][1].update({Portdst: [1, list, description, nflows, StartTime, StartTime, level] })
		else:
			threads[index].AlertsList.update({tag: [1, { Portdst: [ 1, list, description, nflows, StartTime, StartTime, level] } ] })

#Check ICMP Dos/DDos Attacks
class ICMPDoS(threading.Thread):
	def __init__(self, index):
		threading.Thread.__init__(self)
		self._stopevent = threading.Event()
		self.index = index
		self.ICMP_PORT_DEST_UNREACH_LIST = {768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783}
		self.ICMP_PORT_REDIRECT_LIST = {1280, 1281, 1282, 1283} 
		self.ICMP_PORT_TIME_EXCEEDED_LIST = {2816, 2817}
		self.hashtable_IPsrc = {}
		self.TOTAL_ICMP_ECHO = 0
		self.TOTAL_ICMP_ECHO_REPLY = 0
		self.TOTAL_ICMP_TIME_EXCEEDED = 0
		self.TOTAL_ICMP_DEST_UNREACH = 0
		self.TOTAL_ICMP_REDIRECT = 0

		self.ICMP_ECHO_LIST = {}
		self.ICMP_ECHO_REPLY_LIST = {}
		self.ICMP_TIME_EXCEEDED_LIST = {}
		self.ICMP_DEST_UNREACH_LIST = {}
		self.ICMP_REDIRECT_LIST = {}

		self.StartTime = 0
		self.tag = ''
		self.nflows = 0
		self.count = 0
		self.rate = 0
		self.level = ''
		self.description = ''
		self.list = {}

	def run(self):
		while not self._stopevent.isSet():
			if len(threads[self.index].ICMPflowList_IPsrc) > 0:
				self.hashtable_IPsrc = threads[self.index].ICMPflowList_IPsrc.copy()
				for IPsrc in self.hashtable_IPsrc.keys():
					self.count = 0
					self.rate = 0
					self.level = ''
					self.description = ''
					self.StartTime = 0
					self.nflows = 0
					self.tag = ''
					self.list = {}
					if self.hashtable_IPsrc[IPsrc][3].has_key(2048):
						self.TOTAL_ICMP_ECHO += 1
						if self.ICMP_ECHO_LIST.has_key(IPsrc):          
							self.ICMP_ECHO_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][2048][0]                                                      
						else:
							self.ICMP_ECHO_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][2048][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})								
						self.rate =  int(round((self.TOTAL_ICMP_ECHO*100)/MAX_ICMP_ECHO))
						self.description = 'ICMP FLOODING ATTACKS / ' + dicicmpdef[2048]
						self.list = self.ICMP_ECHO_LIST
						self.nflows = self.TOTAL_ICMP_ECHO
						self.StartTime = time.time()
						self.tag = 'IFD'
						createICMPAlert(2048, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.index)
						removeEntryHashtable(IPsrc, 2048, '', threads[self.index].ICMPflowList_IPsrc)
					elif self.hashtable_IPsrc[IPsrc][3].has_key(0):
						self.TOTAL_ICMP_ECHO_REPLY += 1
						if self.ICMP_ECHO_REPLY_LIST.has_key(IPsrc):
							self.ICMP_ECHO_REPLY_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][0][0]
						else:
							self.ICMP_ECHO_REPLY_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][0][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
						self.rate =  int(round((self.TOTAL_ICMP_ECHO_REPLY*100)/MAX_ICMP_ECHO_REPLY))
						self.description = 'ICMP SMURF ATTACKS / ' + dicicmpdef[0]
						self.list = self.ICMP_ECHO_REPLY_LIST
						self.nflows = self.TOTAL_ICMP_ECHO_REPLY
						self.StartTime = time.time()
						self.tag = 'ISA'
						createICMPAlert(0, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.index)
						removeEntryHashtable(IPsrc, 0, '', threads[self.index].ICMPflowList_IPsrc)
					for Portdst in self.ICMP_PORT_DEST_UNREACH_LIST:
						if self.hashtable_IPsrc[IPsrc][3].has_key(Portdst):
							self.TOTAL_ICMP_DEST_UNREACH += 1
							if self.ICMP_DEST_UNREACH_LIST.has_key(IPsrc):
								self.ICMP_DEST_UNREACH_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][0]
							else:
								self.ICMP_DEST_UNREACH_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
							self.rate =  int(round((self.TOTAL_ICMP_DEST_UNREACH*100)/MAX_ICMP_DEST_UNREACH))
							self.description = 'ICMP DEST UNREACH VIOLATIONS / ' + dicicmpdef[Portdst]
							self.list = self.ICMP_DEST_UNREACH_LIST
							self.nflows = self.TOTAL_ICMP_DEST_UNREACH
							self.StartTime = time.time()
							self.tag = 'IDUV'
							createICMPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.index)
							removeEntryHashtable(IPsrc, Portdst, '', threads[self.index].ICMPflowList_IPsrc)
					for Portdst in self.ICMP_PORT_REDIRECT_LIST:
						if self.hashtable_IPsrc[IPsrc][3].has_key(Portdst):
							self.TOTAL_ICMP_REDIRECT += 1
							if self.ICMP_REDIRECT_LIST.has_key(IPsrc):
								self.ICMP_REDIRECT_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][0]
							else:
								self.ICMP_REDIRECT_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})
							self.rate =  int(round((self.TOTAL_ICMP_REDIRECT*100)/MAX_ICMP_REDIRECT))
							self.description = 'ICMP REDIRECT VIOLATIONS / ' + dicicmpdef[Portdst]
							self.list = self.ICMP_REDIRECT_LIST
							self.nflows = self.TOTAL_ICMP_REDIRECT
							self.StartTime = time.time()
							self.tag = 'IRV'
							createICMPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.index)
							removeEntryHashtable(IPsrc, Portdst, '', threads[self.index].ICMPflowList_IPsrc)
					for Portdst in self.ICMP_PORT_TIME_EXCEEDED_LIST:
						if self.hashtable_IPsrc[IPsrc][3].has_key(Portdst):
							self.TOTAL_ICMP_TIME_EXCEEDED += 1
							if self.ICMP_TIME_EXCEEDED_LIST.has_key(IPsrc):
								self.ICMP_TIME_EXCEEDED_LIST[IPsrc][0] += self.hashtable_IPsrc[IPsrc][3][Portdst][0]
							else:
								self.ICMP_TIME_EXCEEDED_LIST.update({IPsrc : [self.hashtable_IPsrc[IPsrc][3][Portdst][0], self.hashtable_IPsrc[IPsrc][1], self.hashtable_IPsrc[IPsrc][2]]})				
							self.rate =  int(round((self.TOTAL_ICMP_TIME_EXCEEDED*100)/MAX_ICMP_TIME_EXCEEDED))
							self.description = 'ICMP TIME EXCEEDED VIOLATIONS / ' + dicicmpdef[Portdst]
							self.list = self.ICMP_TIME_EXCEEDED_LIST
							self.nflows = self.TOTAL_ICMP_TIME_EXCEEDED
							self.StartTime = time.time()
							self.tag = 'ITEV'
							createICMPAlert(Portdst, self.rate, self.level, self.list, self.nflows, self.tag, self.description, self.StartTime, self.index)
							removeEntryHashtable(IPsrc, Portdst, '', threads[self.index].ICMPflowList_IPsrc)   
		#self._stopevent.wait(DELAY)
		#print "Stop Checking ICMP Scans..."

	def stop(self):
		self._stopevent.set()		

#Server Threading Class
class ConfigServ(threading.Thread):
	def __init__(self, IPServ):
		threading.Thread.__init__(self)		
		self._stopevent = threading.Event()
		self.index = 0 # Server Thread Index		
		self.IPServ = IPServ # The Server IP Address
		self.PortDstList = Set() # Collections of Destination Port Number opened and used by server
		self.maxTCPClients = 0 # Maximum Number of TCP client connections allowed 
		self.maxLatency = None # Maximum Acceptable Latency in milliseconds
		self.maxSynBacklog = 0 # Maximum Acceptable SYN Request allowed to keep in memory by the kernel
		self.TCPflowList_IPsrc = {} # List of TCP Flows From Source IP Address Filtered by the server
		self.UDPflowList_IPsrc = {} # List of UDP Flows From Source IP Address Filtered by the server
		self.ICMPflowList_IPsrc = {} # List of ICMP Flows From Source IP Address Filtered by the server
		self.TCPflowList_IPServ = {} # List of TCP Flows From Server IP Address Filtered by the server
		self.ICMPflowList_IPServ = {} # List of ICMP Flows From Server IP Address Filtered by the server
		self.AlertsList = {} # List of DoS or DDoS attacks detected
		self.ThreadsList = [] # List of Threads for detecting DoS / DDoS Attacks

	def run(self):
		try:
			#Create Threads
			TCP = TCPDoS(self.index)
			UDP = UDPDoS(self.index)
			ICMP = ICMPDoS(self.index)
			#Start threads
			TCP.start()
			UDP.start()
			ICMP.start()
			#Add threads to thread list
			self.ThreadsList.append(TCP)
			self.ThreadsList.append(UDP)
			self.ThreadsList.append(ICMP)
			while not self._stopevent.isSet():
				time.sleep(90)
				if checkLatency(self.PortDstList, self.IPServ) >= self.maxLatency:
					if self.AlertsList.has_key('DOWN'):
						self.AlertsList['DOWN'][0] += 1
						self.AlertsList['DOWN'][5] = time.time()
					else:
						self.AlertsList.update({'DOWN': [1, {}, 'SERVER DOWN !!!', 0, time.time(), time.time(), 'Critical'] })
						#Stop all threads gracefully
						for t in ThreadsList:
							if t.isAlive():
								t.stop()
			#self._stopevent.wait(DELAY)
			#print "Stop Server Thread..."
		except KeyboardInterrupt:
			exit_p()
							
	def stop(self):
		#Stop all threads gracefully
		for t in ThreadsList:
                	if t.isAlive():
                        	t.stop()
		self._stopevent.set()	

#Exit program
def exit_p():
	#Stop all threads gracefully
	for t in threads:
		if t.isAlive():
			t.stop()
	print "Exiting Main thread..."
	print "Exiting Program..."
	sys.exit()

#Start Process
def start_p():
	try:
		#Starting process...
		confServParser()
		#Create Threads
		sniffer = Sniffer()
		parser = Parser(queue)
		wls = WLS()
		#print "Type 'exit' or 'CTRL+C' to quit the program"
		#Start threads
		sniffer.start()
		parser.start()
		wls.start()
		#Add threads to thread list
		threads.append(sniffer)
		threads.append(parser)
		threads.append(wls)
	except:
		print "Error: unable to start thread"
	
	#finally:
		#exit_p()
#Main Process
def main():
	try:
		start_p()
	except KeyboardInterrupt:
		exit_p()

#Main Thread
if __name__ == "__main__":
	main()
