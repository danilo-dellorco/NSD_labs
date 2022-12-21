#configure saddr_db map (XXX key: prefix|addr)
#insert match field 10.0.0.0/24 - key 0x180000000a000000 (0x18 = 24), bitv 11110000 = 0xf0 
bpftool map update name saddr_db key hex 18 00 00 00 0a 00 00 00 value hex f0 00 00 00
#insert match field 10.0.0.0/8 - key  0x080000000a000000 (0x08 = 8), bitv 01110000 = 0x70
bpftool map update name saddr_db key hex 08 00 00 00 0a 00 00 00 value hex 70 00 00 00
#insert match fiel 0/0 - key  0x0000000000000000, bitv 00110000 = 0x30
bpftool map update name saddr_db key hex 00 00 00 00 00 00 00 00 value hex 30 00 00 00

#configure daddr_db map (XXX key: prefix|addr)
#insert match field 10.0.0.0/8 - key 0x080000000a000100 (0x08 = 8), bitv 11000000 = 0xc0
bpftool map update name daddr_db key hex 08 00 00 00 0a 00 00 00 value hex c0 00 00 00
#insert match field 10.0.1.0/24 - key  0x180000000a0000101 (0x18 = 24), bitv 11100000 = 0xe0
bpftool map update name daddr_db key hex 18 00 00 00 0a 00 01 00 value hex e0 00 00 00
#insert match field 8.8.8.8/32 - key  0x2000000008080808 (0x20 = 32), bitv 10010000 = 0x90
bpftool map update name daddr_db key hex 20 00 00 00 08 08 08 08 value hex 90 00 00 00
#insert match fiel 0/0 - key  0x0000000000000000, bitv 10000000 = 0x80
bpftool map update name daddr_db key hex 00 00 00 00 00 00 00 00 value hex 80 00 00 00

#configure sport_db map
#insert match field 10000 - key 0x2710 (0x2710 in network order = 10000), bitv 11110000 = 0xf0
bpftool map update name sport_db key hex 27 10 value hex f0 00 00 00
#insert match field 0 (don't care) - key  0x0000000000000000, bitv 11010000 = 0xd0
bpftool map update name sport_db key hex 00 00 value hex d0 00 00 00

#configure dport_db map
#insert match field 22 - key 0x0016 (0x0016 in network order = 22), bitv 10000000 = 0x80
bpftool map update name dport_db key hex 00 16 value hex 80 00 00 00
#insert match field 80 - key 0x0050 (0x050 in network order = 80), bitv 01100000 = 0x60
bpftool map update name dport_db key hex 00 50 value hex 60 00 00 00
#insert match field 53 - key 0x0035 (0x0035 in network order = 35), bitv 00010000 = 0x10
bpftool map update name dport_db key hex 00 35 value hex 10 00 00 00

#configure proto_db map
#insert match field TCP - key 0x06, bitv 11100000 = 0xe0
bpftool map update name proto_db key hex 06 value hex e0 00 00 00
#insert match field UDP - key 0x11, bitv 10010000 = 0x90 
bpftool map update name proto_db key hex 11 value hex 90 00 00 00
#insert match field 0 (don't care) - key  0x0000000000000000, bitv 10000000 = 0x80
bpftool map update name proto_db key hex 00 value hex 80 00 00 00

