#******************************************************************
# FILE: detect_devices.py
# DESCRIPTION: This script uses scapy to detect Wi-Fi devices from a environment using probe requests without authentication. 
#              Before using it, set your network interface to monitor mode.
# VERSION: 0.0.1
# AUTHOR: R.S. Pissardini
# LICENSE: MIT License. 
#******************************************************************/
from scapy.all import * 

def PacketHandler(pkt):
    if pkt.haslayer(Dot11) :
        info = {'macaddr': pkt.addr2.upper(), 'ssid': pkt.info}
        print "MAC: %(macaddr)s and SSID: %(ssid)s" % info

sniff(iface="wlan0", prn=PacketHandler, store=False, 
    lfilter=lambda p: p.haslayer(Dot11ProbeReq))
