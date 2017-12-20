#!/usr/bin/python
#
# wifiexplorer-sensor.py
# This script enables remote scanning in WiFi Explorer Pro.
# Version 2.0
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. YOU MAY 
# NOT COPY, MODIFY, SUBLICENSE, OR DISTRIBUTE THIS SOFTWARE.
#
# Copyright (c) 2017 Adrian Granados. All rights reserved.
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

interface = ''  # e.g. wlan0
channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, \
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161,
            165]
unsupported_channels = set()

mindwelltime = 0.060
maxdwelltime = 0.120
dwelltimes = {}  # a map of ch, dwelltime
count = 0  # number of captured packets during dwelltime

networks = {}

sniffing = False  # flag to stop sniffer
running = False  # flag to stop main loop

lock = threading.Lock()

def error(message):
    if message:
        print '> (error) {0}'.format(message)


def info(message):
    if message:
        print '> (info) {0}'.format(message)


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


def channel_to_frequency(ch):
    if ch < 14:
        return 2407 + ch * 5

    if ch == 14:
        return 2484

    return (ch + 1000) * 5


def channel_hopper():
    global count

    # Get the index of the interface
    pack = struct.pack('16sI', interface, 0)
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
            time.sleep(0.02)
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
    success = os.system("iwconfig %s mode %s" % (interface, mode)) == 0
    os.system("ip link set %s up" % interface)
    return success


def signal_handler(signal, frame):
    sniffing = False
    running = False
    sys.exit(0)


if __name__ == "__main__":

    if os.geteuid() != 0:
        print "You need to have root privileges to run this script."
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

    # Start server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind(('0.0.0.0', port))
        s.listen(10)
        running = True
        while running:
            info("ready")
            conn, addr = s.accept()
            remote_addr = conn.getpeername()

            # Set interface in monitor mode
            if interface_mode("Monitor"):

                sniffing = True

                t = threading.Thread(target=packet_sniffer, args=())
                t.daemon = True
                t.start()

                try:
                    info("connected to " + remote_addr[0])
                    while sniffing:
                        if channel_hopper() == 0:
                            lock.acquire()
                            found = networks.copy()
                            networks.clear()
                            lock.release()
                            conn.sendall(struct.pack("!I", len(found.keys())))
                            for key in found:
                                conn.sendall(struct.pack("!I", len(found[key])) + str(found[key]))
                        else:
                            break

                except socket.error:
                    pass

                sniffing = False
                t.join()
            else:
                error("failed to set monitor mode")

            conn.close()
            info("disconnected from " + remote_addr[0])

            # Set interface in managed mode
            interface_mode("Managed")

    except socket.error as msg:
        error("bind failed: " + str(msg[0]) + " (" + msg[1] + ")")
        sys.exit(-1)

    s.close()
