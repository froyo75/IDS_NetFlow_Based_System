##########################################################################################
##                                                                         				##
## netflowV9.py --- Cisco NetFlow Version 9 support for Scapy ---          				##
##   																					##
##	see -> http://www.cisco.com/en/US/technologies/tk648/tk362/..						##
##		 ..technologies_white_paper09186a00800a3db9_ps6601_Products_White_Paper.html	##
##		-> http://www.ietf.org/rfc/rfc3954.txt 											##
##		-> http://www.secdev.org/projects/scapy 										##
##      for more informations                                      						##
##                                                                         				##
##     Copyright (C) 2012 :     Froyo  													##
##                     							  										##
##                                                                                     	##
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

from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import UDP
from scapy.layers.inet6 import *

######################################################
####Cisco NetFlow Version 9 Field Type Definitions####
######################################################

IP_PROTOS=load_protocols("/etc/protocols")

class IN_BYTES(Packet):
	name = "NetFlow V9 Field Type IN_BYTES"
	fields_desc = [ IntField("IN_BYTES", 0) ]
	
class IN_PKTS(Packet):
	name = "NetFlow V9 Field Type IN_PKTS"
	fields_desc = [ IntField("IN_PKTS", 0) ]

class FLOWS(Packet):
	name = "NetFlow V9 Field Type FLOWS"
	fields_desc = [ IntField("FLOWS", 0) ]

class PROTOCOL(Packet):
	name = "NetFlow V9 Field Type PROTOCOL"
	fields_desc = [ ByteEnumField("PROTOCOL", 0, IP_PROTOS) ]

class SRC_TOS(Packet):
	name = "NetFlow V9 Field Type TOS"
	fields_desc = [ XByteField("SRC_TOS", 0) ]

class TCP_FLAGS(Packet):
	name = "NetFlow V9 Field Type TCP_FLAGS"
	fields_desc = [ FlagsField("TCP_FLAGS", 0x2, 8, "FSRPAUEC") ]

class L4_SRC_PORT(Packet):
	name = "NetFlow V9 Field Type L4_SRC_PORT"
	fields_desc = [ ShortField("L4_SRC_PORT", 0) ]

class IPV4_SRC_ADDR(Packet):
	name = "NetFlow V9 Field Type IPV4_SRC_ADDR"
	fields_desc = [ IPField("IPV4_SRC_ADDR", "0.0.0.0") ]

class SRC_MASK(Packet):
	name = "NetFlow V9 Field Type SRC_MASK"
	fields_desc = [ ByteField("SRC_MASK", 0) ]

class INPUT_SNMP(Packet):
	name = "NetFlow V9 Field Type INPUT_SNMP"
	fields_desc = [ ShortField("INPUT_SNMP", 0) ]

class L4_DST_PORT(Packet):
	name = "NetFlow V9 Field Type L4_DST_PORT"
	fields_desc = [ ShortField("L4_DST_PORT", 0) ]

class IPV4_DST_ADDR(Packet):
	name = "NetFlow V9 Field Type IPV4_DST_ADDR"
	fields_desc = [ IPField("IPV4_DST_ADDR", "0.0.0.0") ]

class DST_MASK(Packet):
	name = "NetFlow V9 Field Type DST_MASK"
	fields_desc = [ ByteField("DST_MASK", 0) ]

class OUTPUT_SNMP(Packet):
	name = "NetFlow V9 Field Type OUTPUT_SNMP"
	fields_desc = [ ShortField("OUTPUT_SNMP", 0) ]

class IPV4_NEXT_HOP(Packet):
	name = "NetFlow V9 Field Type IPV4_NEXT_HOP"
	fields_desc = [ IPField("IPV4_NEXT_HOP", "0.0.0.0") ]

class SRC_AS(Packet):
	name = "NetFlow V9 Field Type SRC_AS"
	fields_desc = [ ShortField("SRC_AS", 0) ]

class DST_AS(Packet):
	name = "NetFlow V9 Field Type DST_AS"
	fields_desc = [ ShortField("DST_AS", 0) ]

class BGP_IPV4_NEXT_HOP(Packet):
	name = "NetFlow V9 Field Type BGP_IPV4_NEXT_HOP"
	fields_desc = [ IPField("BGP_IPV4_NEXT_HOP", "0.0.0.0") ]

class MUL_DST_PKTS(Packet):
	name = "NetFlow V9 Field Type MUL_DST_PKTS"
	fields_desc = [ IntField("MUL_DST_PKTS", 0) ]

class MUL_DST_BYTES(Packet):
	name = "NetFlow V9 Field Type MUL_DST_BYTES"
	fields_desc = [ IntField("MUL_DST_BYTES", 0) ]

class LAST_SWITCHED(Packet):
	name = "NetFlow V9 Field Type LAST_SWITCHED"
	fields_desc = [ IntField("LAST_SWITCHED", 0) ]
	
class FIRST_SWITCHED(Packet):
	name = "NetFlow V9 Field Type FIRST_SWITCHED"
	fields_desc = [ IntField("FIRST_SWITCHED", 0) ]

class OUT_BYTES(Packet):
	name = "NetFlow V9 Field Type OUT_BYTES"
	fields_desc = [ IntField("OUT_BYTES", 0) ]

class OUT_PKTS(Packet):
	name = "NetFlow V9 Field Type OUT_PKTS"
	fields_desc = [ IntField("OUT_PKTS", 0) ]

class MIN_PKT_LNGTH(Packet):
	name = "NetFlow V9 Field Type MIN_PKT_LNGTH"
	fields_desc = [ ShortField("MIN_PKT_LNGTH", 0) ]

class MAX_PKT_LNGTH(Packet):
	name = "NetFlow V9 Field Type MAX_PKT_LNGTH"
	fields_desc = [ ShortField("MAX_PKT_LNGTH", 0) ]

class IPV6_SRC_ADDR(Packet):
	name = "NetFlow V9 Field Type IPV6_SRC_ADDR"
	fields_desc = [ SourceIP6Field("IPV6_SRC_ADDR", 0) ]
	
class IPV6_DST_ADDR(Packet):
	name = "NetFlow V9 Field Type IPV6_DST_ADDR"
	fields_desc = [ IP6Field("IPV6_DST_ADDR", 0) ]

class IPV6_SRC_MASK(Packet):
	name = "NetFlow V9 Field Type IPV6_SRC_MASK"
	fields_desc = [ ByteField("IPV6_SRC_MASK", 0) ]
	
class IPV6_DST_MASK(Packet):
	name = "NetFlow V9 Field Type IPV6_DST_MASK"
	fields_desc = [ ByteField("IPV6_DST_MASK", 0) ]

class IPV6_FLOW_LABEL(Packet):
	name = "NetFlow V9 Field Type IPV6_FLOW_LABEL"
	fields_desc = [ BitField("IPV6_FLOW_LABEL", 0, 24) ]

class ICMP_TYPE(Packet):
	name = "NetFlow V9 Field Type ICMP_TYPE"
	fields_desc = [ ShortField("ICMP_TYPE", 0) ]

igmptypes = { 0x11 : "Group Membership Query",
              0x12 : "Version 1 - Membership Report",
	      0x16 : "Version 2 - Membership Report",
	      0x17 : "Leave Group" }
	          
class MUL_IGMP_TYPE(Packet):
	name = "NetFlow V9 Field Type MUL_IGMP_TYPE"
	fields_desc = [ ByteEnumField("MUL_IGMP_TYPE", 0x11, igmptypes) ]

class SAMPLING_INTERVAL(Packet):
	name = "NetFlow V9 Field Type SAMPLING_INTERVAL"
	fields_desc = [ IntField("SAMPLING_INTERVAL", 0) ]
	
class SAMPLING_ALGORITHM(Packet):
	name = "NetFlow V9 Field Type SAMPLING_ALGORITHM"
	fields_desc = [ ByteEnumField("SAMPLING_ALGORITHM", 0x01, {0x01:"Deterministic Sampling", 0x02:"Random Sampling"}) ]

class FLOW_ACTIVE_TIMEOUT(Packet): #Timeout value (in seconds)
	name = "NetFlow V9 Field Type FLOW_ACTIVE_TIMEOUT"
	fields_desc = [ ShortField("FLOW_ACTIVE_TIMEOUT", 0) ]

class FLOW_INACTIVE_TIMEOUT(Packet): #Timeout value (in seconds)
	name = "NetFlow V9 Field Type FLOW_INACTIVE_TIMEOUT"
	fields_desc = [ ShortField("FLOW_INACTIVE_TIMEOUT", 0) ]
	
class ENGINE_TYPE(Packet):
	name = "NetFlow V9 Field Type ENGINE_TYPE"
	fields_desc = [ ByteEnumField("ENGINE_TYPE", 0, {0:"RP",1:"VIP/LC",2:"PFC/DFC"}) ]

class ENGINE_ID(Packet):
	name = "NetFlow V9 Field Type ENGINE_ID"
	fields_desc = [ ByteField("ENGINE_ID", 0) ]

class TOTAL_BYTES_EXP(Packet):
	name = "NetFlow V9 Field Type TOTAL_BYTES_EXP"
	fields_desc = [ IntField("TOTAL_BYTES_EXP", 0) ]

class TOTAL_PKTS_EXP(Packet):
	name = "NetFlow V9 Field Type TOTAL_PKTS_EXP"
	fields_desc = [ IntField("TOTAL_PKTS_EXP", 0) ]

class TOTAL_FLOWS_EXP(Packet):
	name = "NetFlow V9 Field Type TOTAL_FLOWS_EXP"
	fields_desc = [ IntField("TOTAL_FLOWS_EXP", 0) ]

class IPV4_SRC_PREFIX(Packet):
	name = "NetFlow V9 Field Type IPV4_SRC_PREFIX"
	fields_desc = [ IPField("IPV4_SRC_PREFIX", "0.0.0.0") ]

class IPV4_DST_PREFIX(Packet):
	name = "NetFlow V9 Field Type IPV4_DST_PREFIX"
	fields_desc = [ IPField("IPV4_DST_PREFIX", "0.0.0.0") ]

mplstypes = { 0x00 : "UNKNOWN",
              0x01 : "TE-MIDPT",
	      0x02 : "ATOM",
	      0x03 : "VPN",
	      0x04 : "BGP",
	      0x05 : "LDP" }
	          
class MPLS_TOP_LABEL_TYPE(Packet):
	name = "NetFlow V9 Field Type MPLS_TOP_LABEL_TYPE"
	fields_desc = [ ByteEnumField("MPLS_TOP_LABEL_TYPE", 0x00, mplstypes) ]

class MPLS_TOP_LABEL_IP_ADDR(Packet):
	name = "NetFlow V9 Field Type MPLS_TOP_LABEL_IP_ADDR"
	fields_desc = [ IPField("MPLS_TOP_LABEL_IP_ADDR", "0.0.0.0") ]

class FLOW_SAMPLER_ID(Packet):
	name = "NetFlow V9 Field Type FLOW_SAMPLER_ID"
	fields_desc = [ ByteField("FLOW_SAMPLER_ID", 0) ]

class FLOW_SAMPLER_MODE(Packet):
	name = "NetFlow V9 Field Type FLOW_SAMPLER_MODE"
	fields_desc = [ ByteEnumField("FLOW_SAMPLER_MODE", 0x01, {0x01:"Deterministic Sampling", 0x02:"Random Sampling"}) ]

class FLOW_SAMPLER_RANDOM_INTERVAL(Packet):
	name = "NetFlow V9 Field Type FLOW_SAMPLER_RANDOM_INTERVAL"
	fields_desc = [ IntField("FLOW_SAMPLER_RANDOM_INTERVAL", 0) ]

class MIN_TTL(Packet):
	name = "NetFlow V9 Field Type MIN_TTL"
	fields_desc = [ ByteField("MIN_TTL", 0) ]
	
class MAX_TTL(Packet):
	name = "NetFlow V9 Field Type MAX_TTL"
	fields_desc = [ ByteField("MAX_TTL", 0) ]

class IPV4_IDENT(Packet):
	name = "NetFlow V9 Field Type IPV4_IDENT"
	fields_desc = [ ShortField("IPV4_IDENT", 0) ]
	
class DST_TOS(Packet):
	name = "NetFlow V9 Field Type DST_TOS"
	fields_desc = [ XByteField("DST_TOS", 0) ]

class IN_SRC_MAC(Packet):
	name = "NetFlow V9 Field Type IN_SRC_MAC"
	fields_desc = [ SourceMACField("IN_SRC_MAC") ]

class OUT_DST_MAC(Packet):
	name = "NetFlow V9 Field Type OUT_DST_MAC"
	fields_desc = [ DestMACField("OUT_DST_MAC") ]
	
class SRC_VLAN(Packet):
	name = "NetFlow V9 Field Type SRC_VLAN"
	fields_desc = [ ByteField("SRC_VLAN", 0) ]

class DST_VLAN(Packet):
	name = "NetFlow V9 Field Type DST_VLAN"
	fields_desc = [ ByteField("DST_VLAN", 0) ]

class IP_PROTOCOL_VERSION(Packet):
	name = "NetFlow V9 Field Type IP_PROTOCOL_VERSION"
	fields_desc = [ ByteField("IP_PROTOCOL_VERSION", 4) ]

class DIRECTION(Packet):
	name = "NetFlow V9 Field Type DIRECTION"
	fields_desc = [ ByteEnumField("DIRECTION", 0, {0:"Ingress Flow",1:"Egress Flow"}) ]

class IPV6_NEXT_HOP(Packet):
	name = "NetFlow V9 Field Type IPV6_NEXT_HOP"
	fields_desc = [ IP6Field("IPV6_NEXT_HOP", 0) ]
	
class BGP_IPV6_NEXT_HOP(Packet):
	name = "NetFlow V9 Field Type BGP_IPV6_NEXT_HOP"
	fields_desc = [ IP6Field("BGP_IPV6_NEXT_HOP", 0) ]

class IPV6_OPTION_HEADERS(Packet):
	name = "NetFlow V9 Field Type IPV6_OPTION_HEADERS"
	fields_desc = [ ByteEnumField("IPV6_OPTION_HEADERS", 59, ipv6nh) ]
	def extract_padding(self, s):
              	return "", s

labelvalues = { 0 : "IPv4 Explicit NULL Label",
              	1 : "Router Alert Label",
	          	2 : "IPv6 Explicit NULL Label",
	          	3 : "Implicit NULL Label" } #Values 4-15 are reserved

class MPLS_LABEL_1(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_1"
	fields_desc = [ BitEnumField("Label 1", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_2(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_2"
	fields_desc = [ BitEnumField("Label 2", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_3(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_3"
	fields_desc = [ BitEnumField("Label 3", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_4(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_4"
	fields_desc = [ BitEnumField("Label 4", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_5(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_5"
	fields_desc = [ BitEnumField("Label 5", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_6(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_6"
	fields_desc = [ BitEnumField("Label 6", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_7(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_7"
	fields_desc = [ BitEnumField("Label 7", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]
					
class MPLS_LABEL_8(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_8"
	fields_desc = [ BitEnumField("Label 8", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_9(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_9"
	fields_desc = [ BitEnumField("Label 9", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class MPLS_LABEL_10(Packet):
	name = "NetFlow V9 Field Type MPLS_LABEL_10"
	fields_desc = [ BitEnumField("Label 10", 0, 20, labelvalues),
					XBitField("Traffic Class", 0, 3),
					BitField("Bottom of Stack", 0, 1) ]

class IN_DST_MAC(Packet):
	name = "NetFlow V9 Field Type IN_DST_MAC"
	fields_desc = [ DestMACField("IN_DST_MAC") ]

class OUT_SRC_MAC(Packet):
	name = "NetFlow V9 Field Type OUT_SRC_MAC"
	fields_desc = [ SourceMACField("OUT_SRC_MAC") ]


#IF_NAME 82 N (default specified in template)
#IF_DESC 83 N (default specified in template)
#SAMPLER_NAME 84 N (default specified in template)

class IN_PERMANENT_BYTES(Packet):
	name = "NetFlow V9 Field Type IN_PERMANENT_BYTES"
	fields_desc = [ IntField("IN_PERMANENT_BYTES", 0) ]

class IN_PERMANENT_PKTS(Packet):
	name = "NetFlow V9 Field Type IN_PERMANENT_PKTS"
	fields_desc = [ IntField("IN_PERMANENT_PKTS", 0) ]

class FRAGMENT_OFFSET(Packet):
	name = "NetFlow V9 Field Type FRAGMENT_OFFSET"
	fields_desc = [ ShortField("FRAGMENT_OFFSET", 0) ]

fsstatus = { 00 : "Unknown",
             01 : "Forwarded",
	     10 : "Dropped",
	     11 : "Consumed" }
	          
rcvalues = { 0 : "Unknown",
	     64 : "Unknown",
	     65 : "Forwarded Fragmented",
             66 : "Forwarded Not Fragmented",
	     128 : "Unknown",
	     129 : "Drop ACL Deny",
             130 : "Drop ACL Drop",
             131 : "Drop Unroutable",
	     132 : "Drop Adjacency",
	     133 : "Drop Fragmentation & DF Set",
	     134 : "Drop Bad Header Checksum",
	     135 : "Drop Bad Total Length",
	     136 : "Drop Bad Header Length",
	     137 : "Drop Bad TTL",
	     138 : "Drop Policer",
	     139 : "Drop WRED",
	     140 : "Drop RPF",
	     141 : "Drop For Us",
	     142 : "Drop Bad Output Interface",
	     143 : "Drop Hardware",
	     192 : "Unknown",
	     193 : "Terminate Punt Adjacency",
	     194 : "Terminate Incomplete Adjacency",
	     195 : "Terminate For Us" }

class FORWARDING_STATUS(Packet):
	name = "NetFlow V9 Field Type FORWARDING_STATUS"
	fields_desc = [ BitEnumField("Status", 0, 2, fsstatus),
					BitEnumField("Reason Code", 0, 6, rcvalues) ]

class MPLS_PAL_RD(Packet):
	name = "NetFlow V9 Field Type MPLS_PAL_RD"
	fields_desc = [ BitField("MPLS_PAL_RD", 0, 64) ]

class MPLS_PREFIX_LEN(Packet):
	name = "NetFlow V9 Field Type MPLS_PREFIX_LEN"
	fields_desc = [ ByteField("MPLS_PREFIX_LEN", 0) ]

class SRC_TRAFFIC_INDEX(Packet):
	name = "NetFlow V9 Field Type SRC_TRAFFIC_INDEX"
	fields_desc = [ IntField("SRC_TRAFFIC_INDEX", 0) ]

class DST_TRAFFIC_INDEX(Packet):
	name = "NetFlow V9 Field Type DST_TRAFFIC_INDEX"
	fields_desc = [ IntField("DST_TRAFFIC_INDEX", 0) ]

#APPLICATION DESCRIPTION (N)
#APPLICATION TAG (1+N)
#APPLICATION NAME (N)

class PostipDiffServCodePoint(Packet):
	name = "NetFlow V9 Field Type PostipDiffServCodePoint"
	fields_desc = [ ByteField("PostipDiffServCodePoint", 0) ]

class Replication_Factor(Packet):
	name = "NetFlow V9 Field Type Replication_Factor"
	fields_desc = [ IntField("Replication_Factor", 0) ]

#DEPRECATED (N)

#layer2packetSectionOffset (Unknown)
#layer2packetSectionSize (Unknown)
#layer2packetSectionData (Unknown)

#105 to 127 **Reserved for future use by cisco**
######################################################

##############################################################
###########Cisco Netflow Protocol version 9 Classes###########
##############################################################

class TemplateRecord(Packet):
	name = "NetFlow V9 Template Record"
	fields_desc = [ ShortField("Type", 0), 
			ShortField("Length", 0) ]
	def extract_padding(self, s):
		return "", s

class TemplateFlowSet(Packet):
	name = "NetFlow V9 Template FlowSet"
    	fields_desc = [ ShortField("TemplateID", 0),
                        FieldLenField("FieldCount", 0, count_of="Records"),
                        PacketListField("Records", None, TemplateRecord, count_from=lambda pkt: pkt.FieldCount)	]		
	def extract_padding(self, s):
              	return "", s

class OptionsTemplateScopeRecord(Packet):
	name = "NetFlow V9 Options Template Scope Record"
	fields_desc = [ ShortEnumField("ScopeFieldType", 1, {1:"System",2:"Line Card",3:"Cache",4:"Template"}),
			ShortField("ScopeFieldLength", 0) ]
	def extract_padding(self, s):
		return "", s

class OptionsTemplateFieldRecord(Packet):
	name = "NetFlow V9 Options Template Field Record"
	fields_desc = [ ShortField("OptionFieldType", 0), 
			ShortField("OptionFieldLength", 0) ]
	def extract_padding(self, s):
		return "", s
				
class OptionsTemplateFlowSet(Packet):
	name = "NetFlow V9 Options Template FlowSet"
	fields_desc = [ ShortField("TemplateID", 0), 
			FieldLenField("OptionScopeLength", 0, length_of="OptionScopes"),
			FieldLenField("OptionLength", 0, length_of="Options"), 
			PacketListField("OptionsScopeRecords", None, OptionsTemplateScopeRecord, length_from=lambda pkt: pkt.OptionScopeLength), 
			PacketListField("OptionsRecords", None, OptionsTemplateFieldRecord, length_from=lambda pkt: pkt.OptionLength) ]
	def extract_padding(self, s):
               	return "", s

class FlowSet(Packet):
	name = "NetFlow V9 FlowSet"
  	fields_desc = [ ShortField("FlowSetID", 0),
			ShortField("Length", 0), 
			ConditionalField(PacketListField("Templates", None, TemplateFlowSet, length_from=lambda pkt: pkt.Length-4), lambda pkt: pkt.FlowSetID == 0),
			ConditionalField(PacketListField("OptionsTemplates", None, OptionsTemplateFlowSet, length_from=lambda pkt: pkt.Length-4), lambda pkt: pkt.FlowSetID == 1),
			ConditionalField(PacketListField("Datas", None, Raw, length_from=lambda pkt: pkt.Length-4), lambda pkt: pkt.FlowSetID > 255) ]
	def extract_padding(self, s):
		return "", s
			   
class Header(Packet):
    	name = "NetFlow V9 Header"
    	fields_desc = [ ShortField("Version", 9),
			FieldLenField("Count", 0, count_of="FlowsetList"),
                    	IntField("SysUptime", 0),
                    	IntField("UnixSecs", 0),
                    	IntField("PackageSequence", 0),
                    	IntField("SourceID", 0),
			PacketListField("FlowsetList", None, FlowSet, count_from=lambda pkt: pkt.Count) ] 

bind_layers(UDP , Header, dport=2055)

##############################################################
################################################
###############################
###################
