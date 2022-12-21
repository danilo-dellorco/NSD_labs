#PASS (key 0)
#dummy ARP request for ip address 0.0.0.0
p=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1)
#dummy ipv6 packet
p=Ether(dst="00:0c:29:76:28:bf")/IPv6()
several strategies are
possible. I have chosen
to use python/scapy to
generate packets and
check for the actual
classification by dumping
the stats map.
#TX (key 2)
#exact match
#dummy IPv4 packet to 8.8.8.8
p=Ether(dst="00:0c:29:76:28:bf")/IP(src="7.7.7.7",dst="8.8.8.8")
#LPM match
#dummy IPv4 packet from 10.0.0.1
p=Ether(dst="00:0c:29:76:28:bf")/IP(src="10.0.0.1",dst="1.1.1.1")
#dummy IPv4 packet from 192.168.0.1
p=Ether(dst="00:0c:29:76:28:bf")/IP(src="192.168.0.1",dst="1.1.1.1")
#DROP (key 1)
p=Ether(dst="00:0c:29:76:28:bf")/IP(src="1.1.1.1",dst="2.2.2.2")
#try and send a ping. arp is passed (response received)
#ping is dropped (no response is received)
#ping 172.16.115.2
#to send packet through proper iface
#my VM is attached to a host only net. On the host iface=bridge100
#sendp(p, iface="bridge100")

sleep(3)
system("bpftool map dump name stats_db")
