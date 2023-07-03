# MAP-T BR Verification Tool

This is a tool to validate MAP-T Border relay functionality. This crafts packets based on input provided such as PSID offset, MAP-T Rule prefix, DMR prefix. The Source IP would be that of a MAP-T CE device such as an RG along with defined allowable ports. To simulate spoof errors, use the flag genrateIncorrectRanges.

## Requirements 
- go version 1.20.5 and above 
- libpcap-dev
    ```
    sudo apt-get install libpcap-dev
    ```



## Input file 
```
---
dmr-prefix : "2001:db8:1111:2222::/64"
mapt-prefix: "3010:1122::/44"
eabits-len: 12
ipv4-prefix: "12.8.10.0/24"
psid-offset: 6
psid-len : 4
#value set to "true" would craft packets that intentionally fall out of the permissible port ranges and hence BR should not translate it.
generate-incorrect-ranges: false
# This would pick a destination address from the subnet block and randomly generate a packet towards it.
dest-v4-ip : "99.99.99.0/24"
# pkt-intf is the interface over which the generated packets will be sent
pkt-intf : "eth1"
smac : "02:aa:01:40:01:00"
dmac : "02:aa:01:10:02:01"
# pkt-type can be udp or icmp
pkt-type: "udp"
```

## Usage

```
./mapt-br-verification help

	==============  MAP-T BR Verification Tool  ================
	Version: 1.0

	Usage: 
    1. ./mapt-br-verification <input.yaml> save
    2. ./mapt-br-verification <input.yaml> generate

	This will craft packets within the defined ranges such that the BR would
	translate. The idea is mimic a CPE device generating an IPv4 embedded Ipv6
	address towards the BR.

	when using the flag generate-incorrect-ranges. This will intentially craft a
	packet outside of the range of PSID or use incorrect mapt-prefixes such that
	the BR fails translations.

	The argument save, will save the computed result into a file named MAPT_CE_SIP_DIP.txt
	============================================================
```

### Example to save all combinations to file  
```
 ./mapt-br-verification input.yaml save
 ====Generating RG traffic for below domain configs ===

DMR prefix:  2001:db8:1111:2222::/64
BMR prefix:  3010:1122::/44
PSID offset:  6
PSID len:	 4
Source v4 IP:  12.8.10.0/24
Dest v4 IP:  99.99.99.0/24
num modifier bits:  6
num of usable source ports per ce/PSID:  3969
=======================================================



% more MAPT_CE_SIP_DIP.txt
Source IP: 3010:1122:4::c08:a00:0 Destionation IP: 2001:db8:1111:2222:63:6363:1700:0 Source port: 60461 Destination Port: 21885
Source IP: 3010:1122:4:100:0:c08:a00:1 Destionation IP: 2001:db8:1111:2222:63:6363:a900:0 Source port: 58495 Destination Port: 28463
Source IP: 3010:1122:8:200:0:c08:a00:2 Destionation IP: 2001:db8:1111:2222:63:6363:2c00:0 Source port: 54448 Destination Port: 22056
Source IP: 3010:1122:8:300:0:c08:a00:3 Destionation IP: 2001:db8:1111:2222:63:6363:d700:0 Source port: 63688 Destination Port: 8488
Source IP: 3010:1122:0:400:0:c08:a00:4 Destionation IP: 2001:db8:1111:2222:63:6363:6f00:0 Source port: 56606 Destination Port: 16544
...
```

### Example to pass packets 
```
 ====Generating RG traffic for below domain configs ===

DMR prefix:  2001:db8:1111:2222::/64
BMR prefix:  3010:1122::/44
PSID offset:  6
PSID len:        4
Source v4 IP:  12.8.10.0/24
Dest v4 IP:  99.99.99.0/24
num modifier bits:  6
num of usable source ports per ce/PSID:  3969
=======================================================

sending 1 packet per customer on interface eth1
. Total 4095




root@ubuntu:/opt/mapt-br-verification# tcpdump -nei ub1_map1
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ub1_map1, link-type EN10MB (Ethernet), capture size 262144 bytes
07:38:27.997484 02:aa:01:40:01:00 > 02:aa:01:10:02:01, ethertype IPv6 (0x86dd), length 71: 3010:1122:f:ff00:0:c08:aff:f.56312 > 2001:db8:1111:2222:63:6363:e400:0.63903: UDP, length 9
07:38:28.997726 02:aa:01:40:01:00 > 02:aa:01:10:02:01, ethertype IPv6 (0x86dd), length 71: 3010:1122:f:ff00:0:c08:aff:f.56312 > 2001:db8:1111:2222:63:6363:e400:0.63903: UDP, length 9
07:38:29.997988 02:aa:01:40:01:00 > 02:aa:01:10:02:01, ethertype IPv6 (0x86dd), length 71: 3010:1122:f:ff00:0:c08:aff:f.56312 > 2001:db8:1111:2222:63:6363:e400:0.63903: UDP, length 9
07:38:30.998195 02:aa:01:40:01:00 > 02:aa:01:10:02:01, ethertype IPv6 (0x86dd), length 71: 3010:1122:f:ff00:0:c08:aff:f.56312 > 2001:db8:1111:2222:63:6363:e400:0.63903: UDP, length 9
07:38:31.999031 02:aa:01:40:01:00 > 02:aa:01:10:02:01, ethertype IPv6 (0x86dd), length 71: 3010:1122:f:ff00:0:c08:aff:f.56312 > 2001:db8:1111:2222:63:6363:e400:0.63903: UDP, length 9

```
