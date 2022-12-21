import scapy
import time
import os

# PASS (key 0)
# dummy ARP request for ip address 0.0.0.0
p = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=1)
# dummy ipv6 packet
p = scapy.Ether(dst="00:0c:29:76:28:bf")/scapy.IPv6()
# TX (key 2)
# exact match
# dummy IPv4 packet to 8.8.8.8
p = scapy.Ether(dst="00:0c:29:76:28:bf")/scapy.IP(src="7.7.7.7", dst="8.8.8.8")
# LPM match
# dummy IPv4 packet from 10.0.0.1
p = scapy.Ether(dst="00:0c:29:76:28:bf") / \
    scapy.IP(src="10.0.0.1", dst="1.1.1.1")
# dummy IPv4 packet from 192.168.0.1
p = scapy.Ether(dst="00:0c:29:76:28:bf") / \
    scapy.IP(src="192.168.0.1", dst="1.1.1.1")
# DROP (key 1)
p = scapy.Ether(dst="00:0c:29:76:28:bf")/scapy.IP(src="1.1.1.1", dst="2.2.2.2")
# try and send a ping. arp is passed (response received)
# ping is dropped (no response is received)
# ping 172.16.115.2
# to send packet through proper iface
# my VM is attached to a host only net. On the host iface=bridge100
#sendp(p, iface="bridge100")

time.sleep(3)
os.system("bpftool map dump name stats_db")
