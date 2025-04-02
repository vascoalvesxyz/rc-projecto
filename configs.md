## Router 1
configure terminal

ip nat inside source static tcp 10.20.0.129 443 193.137.101.1 443

interface FastEthernet0/0
ip address 10.20.0.254 255.255.255.128
ip nat inside
no shutdown
exit

interface FastEthernet0/1
ip address 193.137.101.1 255.255.255.128
ip nat outside
no shutdown
exit

ip route 193.137.100.0 255.255.255.0 193.137.101.2
exit

copy running-config startup-config

# Router 2 (Publica)

configure terminal

interface FastEthernet0/0
ip address 193.137.101.2 255.255.255.128
no shutdown
exit

interface FastEthernet0/1
ip address 193.137.100.254 255.255.255.0
no shutdown
exit

exit 

copy running-config startup-config


## Router 3
configure terminal

access-list 30 permit 10.5.2.0 0.0.0.63
ip nat inside source list 30 interface FastEthernet0/0 overload

interface FastEthernet0/0
ip address 193.137.101.3 255.255.255.128
ip nat outside
no shutdown
exit

interface FastEthernet0/1
ip address 10.5.2.62 255.255.255.192
ip nat inside
no shutdown
exit

ip nat inside source static tcp 10.5.2.1 443 193.137.101.3 443
ip nat inside source static tcp 10.5.2.2 444 193.137.101.3 444
ip route 193.137.100.0 255.255.255.0 193.137.101.2

exit 

copy running-config startup-config
