import os
from steelscript.wireshark.core.pcap import PcapFile
import numpy as np
import subprocess
import datetime
import pandas as pd
from io import StringIO

"""
Rename and reorder file
"""

"""
pdf = pcap.query(['frame.time_epoch', 'ip.src', 'ip.dst', 'ip.len', 'ip.proto'],
				starttime = pcap.starttime,
				duration='1min',
				as_dataframe=True)
"""

def gen_data_frame(path_str):
	pcap = PcapFile(path_str)
	#print '========='
	#print repr(pcap.info())
	#print '========='
	pcap.info()

	pdf = pcap.query([
	# 'frame.time_epoch',
	'frame.time_delta',
	# 'frame.pkt_len',
	# 'frame.len',
	# 'frame.cap_len',
	# 'frame.marked',
	'ip.src',
	'ip.dst',
	'ip.len',
	'ip.flags',
	# 'ip.flags.rb',
	# 'ip.flags.df',
	# 'ip.flags.mf',
	# 'ip.frag_offset', # Generates unexpected behaviour in steelscript-wireshark
	'ip.ttl',
	# 'ip.proto',
	# 'ip.checksum_good',
	'tcp.srcport',
	'tcp.dstport',
	'tcp.len',
	# 'tcp.nxtseq',
	# 'tcp.hdr_len',
	# 'tcp.flags.cwr',
	# 'tcp.flags.urg',
	# 'tcp.flags.push',
	# 'tcp.flags.syn',
	# 'tcp.window_size',
	# 'tcp.checksum',
	# 'tcp.checksum_good',
	# 'tcp.checksum_bad',
	# 'udp.length',
	# 'udp.checksum_coverage',
	# 'udp.checksum',
	# 'udp.checksum_good',
	# 'udp.checksum_bad'
	],
	#starttime = pcap.starttime,
	as_dataframe=True)

	"""
	pdf = pcap.query([
	'frame.time_delta',
	'ip.src',
	'ip.dst',
	'ip.len',
	'tcp.srcport',
	'tcp.dstport',
	'tcp.len',
	],
	starttime = pcap.starttime,
	as_dataframe=True)
	"""


	print ('=======')
	print ('pdf len: ') + repr(len(pdf))


	return pdf


def read_pcap(filename, fields=[], display_filter="",
			  timeseries=False, strict=False):
	""" Read PCAP file into Pandas DataFrame object.
	Uses tshark command-line tool from Wireshark.

	filename:       Name or full path of the PCAP file to read
	fields:         List of fields to include as columns
	display_filter: Additional filter to restrict frames
	strict:         Only include frames that contain all given fields
					(Default: false)
	timeseries:     Create DatetimeIndex from frame.time_epoch
					(Default: false)

	Syntax for fields and display_filter is specified in
	Wireshark's Display Filter Reference:

	  http://www.wireshark.org/docs/dfref/
	"""

	"""
	pcap_path = '/home/jon/workspace/pcap-feature-extractor/data/L_cyber_chrome_09-17__11_38_11/L_cyber_chrome_09-17__11_38_11.pcap.TCP_10-0-0-14_35015_192-229-233-25_443.pcap'
	cmd = 'tshark -r %s -T fields -E occurrence=a -E aggregator=, -e frame.time_epoch -e frame.time_delta -e frame.len -e frame.cap_len -e frame.marked -e ip.src -e ip.dst -e ip.len -e ip.flags -e ip.flags.rb -e ip.flags.df -e ip.flags.mf -e ip.frag_offset -e ip.ttl -e ip.proto -e ip.checksum_good -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.nxtseq -e tcp.hdr_len -e tcp.flags.cwr -e tcp.flags.urg -e tcp.flags.push -e tcp.flags.syn -e tcp.window_size -e tcp.checksum -e tcp.checksum_good -e tcp.checksum_bad' % pcap_path
	table = subprocess.check_output(cmd.split())
	df = pd.read_table(StringIO(table), header=None, names=[ ... column names ... ])
	remove from cmd: -n : header=y : -R ''
	"""

	if timeseries:
		fields = ["frame.time_epoch"] + fields
	fieldspec = " ".join("-e %s" % f for f in fields)
	"""
	display_filters = fields if strict else []
	if display_filter:
		display_filters.append(display_filter)
	filterspec = "-R '%s'" % " and ".join(f for f in display_filters)
	"""
	filterspec = ''
	# options = "-r %s -n -T fields -E header=y -E occurrence=a -E aggregator=, " % filename
	options = "-r %s -T fields -E occurrence=a -E aggregator=, " % filename
	cmd = "tshark %s %s %s" % (options, filterspec, fieldspec)
	# print '------------------'
	# print 'cmd: ' + repr(cmd)
	# print '------------------'
	# proc = subprocess.Popen(cmd, shell = True,
	#                              stdout=subprocess.PIPE)
	# table = subprocess.check_output(cmd)

	# pcap_path = '/home/jon/workspace/pcap-feature-extractor/data/L_cyber_chrome_09-17__11_38_11/L_cyber_chrome_09-17__11_38_11.pcap.TCP_10-0-0-14_35015_192-229-233-25_443.pcap'
	# pcap_path = '/home/jon/workspace/pcap-feature-extractor/data/L_cyber_chrome_09-17__11_38_11/L_cyber_chrome_09-17__11_38_11.pcap.TCP_10-0-0-14_33521_212-179-154-238_443.pcap'
	# cmd = 'tshark -r %s -T fields -E occurrence=a -E aggregator=, -e frame.time_epoch -e frame.time_delta -e frame.len -e frame.cap_len -e frame.marked -e ip.src -e ip.dst -e ip.len -e ip.flags -e ip.flags.rb -e ip.flags.df -e ip.flags.mf -e ip.frag_offset -e ip.ttl -e ip.proto -e ip.checksum_good -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.nxtseq -e tcp.hdr_len -e tcp.flags.cwr -e tcp.flags.urg -e tcp.flags.push -e tcp.flags.syn -e tcp.window_size -e tcp.checksum -e tcp.checksum_good -e tcp.checksum_bad' % pcap_path
	# print '------------------'
	# print 'cmd: ' + repr(cmd)
	# print '------------------'

	command = cmd.split()
	table = subprocess.run(command, stdout=subprocess.PIPE).stdout.decode('utf-8')
	#table = subprocess.check_output(command)


	if timeseries:
		df = pd.read_table(StringIO(table),
						index_col = "frame.time_epoch",
						parse_dates=True,
						date_parser=datetime.datetime.fromtimestamp)
	else:
		# df = pd.read_table(StringIO(table))
		df = pd.read_table(StringIO(table), header=None, names=fields)
		# print repr(df)
	return df


""" Returns the upstream flow, downstream flow (in this order) from a given session DataFrame """
def gen_flows_up_down(pcap):

	dst_port = pcap['tcp.dstport'].iloc[0]
	src_port = pcap['tcp.srcport'].iloc[0]

	ip_src = '00.00.00.00'
	ip_dst = '00.00.00.00'

	if  dst_port == 443:
		ip_src = pcap['ip.src'].iloc[0]
		ip_dst = pcap['ip.dst'].iloc[0]
	elif src_port == 443:
		ip_src = pcap['ip.dst'].iloc[0]
		ip_dst = pcap['ip.src'].iloc[0]
	else:
		""" Throw exception? """
		print ('=====')
		print ('Port 443 not found')
		print ('=====')
	# print 'ip_src: ' + repr(ip_src) + ' ip_dst: ' + repr(ip_dst)
	# print
	return pcap[pcap['ip.src']==ip_src], pcap[pcap['ip.src']==ip_dst]
