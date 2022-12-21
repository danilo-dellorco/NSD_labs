#configure saddr_db map (key: prefix|addr)
#insert match field 10.0.0.0/24 - key 0x180000000a000000 (0x18 = 24)
bpftool map update name saddr_db key hex 18 00 00 00 0a 00 00 00 value hex 00
#insert match field 192.168.0.0/16 - key  0x100000000c0a80000 (0x10 = 16)
bpftool map update name saddr_db key hex 10 00 00 00 c0 a8 00 00 value hex 00

#configure daddr_db map
#insert match field 8.8.8.8
bpftool map update name daddr_db key hex 08 08 08 08 value hex 00



