#!/usr/bin/python3
#
# wifiexplorer-sensor.py
# This script enables remote scanning in WiFi Explorer Pro.
# Version 6.0
#
# Copyright (c) 2017 Adrian Granados. All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import signal
import threading
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

port = 26999
maxclients = 30

interface = ''  # e.g. wlan0
channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, \
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161,
            165]
unsupported_channels = set()

mindwelltime = 0.060
maxdwelltime = 0.180
dwelltimes = {}  # a map of ch, dwelltime
count = 0  # number of captured beacons or probe response frames during dwelltime

clients  = []
beacon_or_probe_resp_frames = {}

ctrl_or_data_frames = {}

sniffing = False  # flag to stop sniffer
running = False  # flag to stop main loop

clients_lock  = threading.Lock()
frames_lock = threading.Lock()

def error(message):
    if message:
        print('> (error) {0}'.format(message))


def info(message):
    if message:
        print('> (info) {0}'.format(message))


def server_handler(socket, condition):
    global clients
    global running
    global maxclients
    while running:

        with condition:
            while running and len(clients) >= maxclients:
                condition.wait()

        conn, addr = socket.accept()
        info("client connected: " + conn.getpeername()[0])
        with clients_lock:
            clients.append(conn)
            with condition:
                condition.notify()


def send_results(frames):
    global clients
    disconnected_clients = []

    with clients_lock:
        # Send header (number of results)
        header = struct.pack("!I", len(frames))
        for conn in clients:
            try:
                conn.sendall(header)
            except:
                conn.close()
                disconnected_clients.append(conn)

        # Remove disconnected clients
        if len(disconnected_clients) > 0:
            clients = list(set(clients) - set(disconnected_clients))

        # Send message (results)
        for frame in frames:
            if (sys.version_info > (3, 0)):
                message = struct.pack("!I", len(frame)) + raw(frame)
            else:
                message = struct.pack("!I", len(frame)) + str(frame)

            for conn in clients:
                try:
                    conn.sendall(message)
                except:
                    conn.close()
                    disconnected_clients.append(conn)

        # Remove disconnected clients
        if len(disconnected_clients) > 0:
            clients = list(set(clients) - set(disconnected_clients))


def packet_handler(p):
    global count
    global beacon_or_probe_resp_frames
    if p.haslayer(Dot11) or p.haslayer(Dot11FCS):
        if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
            count += 1
            bssid = p[Dot11].addr3
            with frames_lock:
                beacon_or_probe_resp_frames[bssid] = p
        else:
            type = p[Dot11].type
            subtype = p[Dot11].subtype
            if (type == 1 and (subtype == 9 or subtype == 11)) or (type == 2 and (subtype == 0 or subtype == 8)):
                ra = p[Dot11].addr1
                if (int(ra[0], 16) & 0x01) != 0x01: # Not broadcast or multicast
                    ta = p[Dot11].addr2
                    with frames_lock:
                        ctrl_or_data_frames[ra] = p
                        ctrl_or_data_frames[ta] = p


def packet_sniffer():
    global sniffing
    while sniffing:
        sniff(iface=interface, prn=packet_handler, store=0, timeout=3)


def channel_to_frequency(ch):
    if ch < 14:
        return 2407 + ch * 5

    if ch == 14:
        return 2484

    return (ch + 1000) * 5


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
    
    return 0


def interface_mode(mode):
    # Set interface in managed mode
    os.system("ip link set %s down" % interface)
    success = os.system("iw dev %s set type %s" % (interface, mode)) == 0
    os.system("ip link set %s up" % interface)
    return success


def signal_handler(signal, frame):
    global sniffing
    global running
    sniffing = False
    running = False
    sys.exit(0)


if __name__ == "__main__":

    if os.geteuid() != 0:
        print("You need to have root privileges to run this script.")
        sys.exit(-1)

    if len(sys.argv) < 2:
        print("Usage: wifiexplorer-sensor.py <iface> [port]")
        sys.exit(-1)

    interface = sys.argv[1]

    if len(sys.argv) == 3:
        port = int(sys.argv[2])

    for ch in channels:
        dwelltimes[ch] = maxdwelltime

    # Install Ctrl+C signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Ignore alarm signal (triggered by waking up a WLAN Pi screen)
    signal.signal(signal.SIGALRM, signal.SIG_IGN)
    
    # Create server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind(('0.0.0.0', port))
        s.listen(10)
    except socket.error as msg:
        error("bind failed: " + str(msg[0]) + " (" + msg[1] + ")")
        sys.exit(-1)

    info("ready")

    running = True
    condition = threading.Condition()

    # Start server
    server = threading.Thread(target=server_handler, args=(s, condition))
    server.daemon = True
    server.start()

    while running:

        with condition:
            while running and len(clients) == 0:
                condition.wait()

        # Set interface in monitor mode
        if interface_mode("monitor"):

            sniffing = True
            info("sniffing")

            t = threading.Thread(target=packet_sniffer, args=())
            t.daemon = True
            t.start()

            while running and sniffing:

                if len(clients) == 0:
                    break

                if channel_hopper() == 0:
                    with frames_lock:
                        frames = list(beacon_or_probe_resp_frames.values())
                        frames.extend(list(ctrl_or_data_frames.values()))
                        beacon_or_probe_resp_frames.clear()
                        ctrl_or_data_frames.clear()
                    send_results(frames)
                    with condition:
                        if len(clients) < maxclients:
                            condition.notify()
                else:
                    break

            sniffing = False
            t.join()
        else:
            error("failed to set monitor mode")

        # Clean up
        with clients_lock:
            for conn in clients:
                conn.close()
            clients = []
            with condition:
                condition.notify()
            
        # Set interface in managed mode
        interface_mode("managed")

    info("exiting")
    s.close()
