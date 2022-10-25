net add bridge bridge ports swp1,swp2,swp
net add bridge bridge vids 30

net add interface swp3 bridge access 30

net add vlan 10 ip address 10.0.10.1/24
net add vlan 20 ip address 10.0.20.1/24
net add vlan 30 ip address 10.0.30.1/24

net add dot1x radius shared-secret radiussecret
net add dot1x radius server-ip 10.0.30.2
net add dot1x dynamic-vlan
net add interface swp1,swp2 dot1x
net add dot1x dynamic-vlan require

net commit
