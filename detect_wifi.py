#******************************************************************
# FILE: detect_wifi.py
# DESCRIPTION: This script uses scapy to detect Wi-Fi APs from a environment. 
#              Before using it, set your network interface to monitor mode.
# VERSION: 0.0.1
# AUTHOR: R.S. Pissardini
# LICENSE: MIT License. 
#******************************************************************/

from scapy.all import *

def PacketHandler(pkt) :
  if pkt.haslayer(Dot11) : #802.11
    if pkt.type == 0 and pkt.subtype == 8 :
      if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
          extra = pkt.notdecoded
          rssi = -(256-ord(extra[-4:-3]))
        except:
          rssi = -100

        info = {'rssi': rssi, 'mac': pkt.addr2, 'ssid':pkt.info}
        print "Found SSID: %(ssid)s with MAC: %(mac)s and RSSI: %(rssi)s" % info
        
sniff(iface="wlan0", prn = PacketHandler)
