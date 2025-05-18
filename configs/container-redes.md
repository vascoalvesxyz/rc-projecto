# ----------------------------
# CLIENTE 1
# ----------------------------
auto eth0
iface eth0 inet static
	address 10.5.2.1
	netmask 255.255.255.128
	gateway 10.5.2.62

# ----------------------------
# CLIENTE 2
# ----------------------------
auto eth0
iface eth0 inet static
	address 10.5.2.2
	netmask 255.255.255.128
	gateway 10.5.2.62

# ----------------------------
# CLIENTE 3
# ----------------------------
auto eth0
iface eth0 inet static
	address 193.137.100.1
	netmask 255.255.255.0
	gateway 193.137.100.254

# ----------------------------
# SERVIDOR
# ----------------------------
auto eth0
iface eth0 inet static
	address 10.20.0.129
	netmask 255.255.255.128
	gateway 10.20.0.254
