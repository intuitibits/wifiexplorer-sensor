#!/usr/bin/python3
#
# wifiexplorer-sensor.py
# This script enables remote scanning in WiFi Explorer Pro.
# Version 4.0.1
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
import fcntl

from libnl.attr import nla_put_u32
from libnl.error import errmsg
from libnl.genl.ctrl import genl_ctrl_resolve
from libnl.genl.genl import genl_connect, genlmsg_put
from libnl.msg import nlmsg_alloc
from libnl.nl import nl_send_auto
from libnl.nl80211 import nl80211
from libnl.socket_ import nl_socket_alloc

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
count = 0  # number of captured packets during dwelltime

clients  = []
networks = {}

sniffing = False  # flag to stop sniffer
running = False  # flag to stop main loop

clients_lock  = threading.Lock()
networks_lock = threading.Lock()

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

def send_results(networks):
    global clients
    disconnected_clients = []

    with clients_lock:
        # Send header (number of results)
        header = struct.pack("!I", len(networks.keys()))
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
        for key in networks:
            if (sys.version_info > (3, 0)):
                message = struct.pack("!I", len(networks[key])) + raw(networks[key])
            else:
                message = struct.pack("!I", len(networks[key])) + str(networks[key])

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
    global networks
    if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
        count += 1
        bssid = p[Dot11].addr3
        with networks_lock:
            networks[bssid] = p

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

    # Get the index of the interface
    pack = struct.pack('16sI', interface.encode(), 0)
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = struct.unpack('16sI', fcntl.ioctl(sk.fileno(), 0x8933, pack))
    except (OSError, IOError):
        error('wireless interface {0} does not exist.'.format(interface))
        return -1
    finally:
        sk.close()

    if_index = int(info[1])

    # Open a socket to the kernel
    sk = nl_socket_alloc()
    ret = genl_connect(sk)
    if ret < 0:
        reason = errmsg[abs(ret)]
        error('genl_connect() failed: {0} ({1})'.format(ret, reason))
        return -1

    # Now get the nl80211 driver ID
    driver_id = genl_ctrl_resolve(sk, b'nl80211')
    if driver_id < 0:
        reason = errmsg[abs(driver_id)]
        error('genl_ctrl_resolve() failed: {0} ({1})'.format(driver_id, reason))
        return -1

    # Iterate over channels using the corresponding dwell time
    supported_channels = [x for x in channels if x not in unsupported_channels]
    for ch in supported_channels:

        if not sniffing:
            break

        # Set new channel
        msg = nlmsg_alloc()
        genlmsg_put(msg, 0, 0, driver_id, 0, 0, nl80211.NL80211_CMD_SET_CHANNEL, 0)
        nla_put_u32(msg, nl80211.NL80211_ATTR_IFINDEX, if_index)
        nla_put_u32(msg, nl80211.NL80211_ATTR_WIPHY_FREQ, channel_to_frequency(ch))
        nla_put_u32(msg, nl80211.NL80211_ATTR_WIPHY_CHANNEL_TYPE, nl80211.NL80211_CHAN_WIDTH_20)

        if nl_send_auto(sk, msg) < 0:
            unsupported_channels.add(ch)
            time.sleep(0.01)
        else:
            count = 0
            time.sleep(dwelltimes[ch])
            if count == 0:
                dwelltimes[ch] = mindwelltime
            else:
                dwelltimes[ch] = maxdwelltime

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
                    with networks_lock:
                        found = networks.copy()
                        networks.clear()
                    send_results(found)
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
