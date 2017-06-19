#!/usr/bin/python
#
# wifiexplorer-sensor.py
# This script enables remote scanning in WiFi Explorer Pro.
# Version 1.0.2
# 
# Copyright (c) 2017 Adrian Granados. All rights reserved.
#

import sys, os, signal
import threading
import re
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


port         = 26999

interface    = '' # e.g. wlan0
channels     = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, \
		36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
unsupported_channels = set()

mindwelltime = 0.060
maxdwelltime = 0.120 
dwelltimes   = {} # a map of ch, dwelltime
count        = 0  # number of captured packets during dwelltime

networks     = {}

sniffing     = False # flag to stop sniffer
running      = False # flag to stop main loop

lock         = threading.Lock()


def packet_handler(p):
	global count
	global networks
	if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
		count += 1
		bssid = p[Dot11].addr3
		lock.acquire()
		networks[bssid] = p
		lock.release()

def packet_sniffer():
	global sniffing
	while sniffing:
		sniff(iface=interface, prn=packet_handler, store=0, timeout=3)

def channel_hopper():
	global count
        supported_channels = [x for x in channels if x not in unsupported_channels]
	for ch in supported_channels:
		if os.system("iw %s set channel %d HT20 > /dev/null 2>&1" % (interface, ch)) == 0:
			count = 0
			time.sleep(dwelltimes[ch])
			if count == 0:
				dwelltimes[ch] = mindwelltime
			else:
				dwelltimes[ch] = maxdwelltime
		else:
                        unsupported_channels.add(ch)
			time.sleep(0.02)

def interface_mode(mode):
	# Set interface in managed mode
        os.system("ip link set %s down" % interface)
        success = os.system("iwconfig %s mode %s" % (interface, mode)) == 0
        os.system("ip link set %s up" % interface)
	return success

def signal_handler(signal, frame):
	sniffing = False
	running = False
	interface_mode("Managed")
	sys.exit(0)

if __name__ == "__main__":
	if os.geteuid() != 0:
		print "You need to have root privileges to run this script."
		sys.exit(-1)

	if len(sys.argv) < 2:
		print("Usage: wifiexplorer-sensor.py <iface>")
		sys.exit(-1)

	interface = sys.argv[1]

	for ch in channels:
	    dwelltimes[ch] = maxdwelltime

	# Install Ctrl+C signal handler
	signal.signal(signal.SIGINT, signal_handler)

	# Start server
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	

	try:
		s.bind( ('0.0.0.0', port) )
		s.listen(10)
		running = True
		while running:
                        print "> ready"
			conn, addr = s.accept()
                        remote_addr = conn.getpeername()

			# Set interface in monitor mode
			if interface_mode("Monitor"):
			
				sniffing = True

				t = threading.Thread(target=packet_sniffer, args=())
				t.daemon = True
				t.start()

				try:
                                        print "> connected to " + remote_addr[0]
					while sniffing:
						channel_hopper()
						lock.acquire()
						found = networks.copy()
                        			networks.clear()
						lock.release()
						conn.sendall(struct.pack("!I", len(found.keys())))
						for key in found:
							conn.sendall(struct.pack("!I", len(found[key])) + str(found[key]))


				except socket.error:
					conn.close()

				sniffing = False
				t.join()
			else:
                                print "> failed to set monitor mode"
				conn.close()

                        print "> disconnected from " + remote_addr[0]

			# Set interface in managed mode
			interface_mode("Managed")
						
	except socket.error as msg:
		print "> bind failed with error: " + str(msg[0]) + " (" + msg[1] + ")"
		sys.exit(-1)

	s.close()
