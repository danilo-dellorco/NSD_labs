from scapy.all import *
import time
import os

# PASS (key 0)
# dummy ARP request for ip address 0.0.0.0
p1 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1)
# dummy ipv6 packet
p2 = Ether(dst="00:0c:29:76:28:bf")/IPv6()
# TX (key 2)
# exact match
# dummy IPv4 packet to 8.8.8.8
p3 = Ether(dst="00:0c:29:76:28:bf")/IP(src="7.7.7.7", dst="8.8.8.8")
# LPM match
# dummy IPv4 packet from 10.0.0.1
p4 = Ether(dst="00:0c:29:76:28:bf") / \
    IP(src="10.0.0.1", dst="1.1.1.1")
# dummy IPv4 packet from 192.168.0.1
p5 = Ether(dst="00:0c:29:76:28:bf") / \
    IP(src="192.168.0.1", dst="1.1.1.1")
# DROP (key 1)
p6 = Ether(dst="00:0c:29:76:28:bf")/IP(src="1.1.1.1", dst="2.2.2.2")

# try and send a ping. arp is passed (response received)
# ping is dropped (no response is received)
# ping 172.16.115.2
# to send packet through proper iface
# my VM is attached to a host only net. On the host iface=bridge100
print("Packets Generated. Start Sending...")
sendp(p1, iface="enp0s3")
print("Packet 1 Sent to Host")
sendp(p2, iface="enp0s3")
print("Packet 2 Sent to Host")
sendp(p3, iface="enp0s3")
print("Packet 3 Sent to Host")
sendp(p4, iface="enp0s3")
print("Packet 4 Sent to Host")
