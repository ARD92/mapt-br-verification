# MAP-T BR Verification Tool

This is a tool to validate MAP-T Border relay functionality. This crafts packets based on input provided such as PSID offset, MAP-T Rule prefix, DMR prefix following RFC 7597 and rfc7599. The Source IP would be that of a MAP-T CE device such as an RG along with defined allowable ports. To simulate spoof errors, use the flag genrateIncorrectRanges.

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

### Validating the above on vMX

### Configure MAP-T
```
set services service-set sset1 softwire-rules sw-rule1
set services service-set sset1 softwire-rules sw-rule2

set services service-set sset1 next-hop-service inside-service-interface si-0/0/0.1
set services service-set sset1 next-hop-service outside-service-interface si-0/0/0.2

set services softwire softwire-concentrator map-t mapt-domain-1 dmr-prefix 2001:db8:1111:2222::/64
set services softwire softwire-concentrator map-t mapt-domain-1 ipv4-prefix 12.8.10.0/24
set services softwire softwire-concentrator map-t mapt-domain-1 mapt-prefix 3010:1122:1100::/44
set services softwire softwire-concentrator map-t mapt-domain-1 ea-bits-len 12
set services softwire softwire-concentrator map-t mapt-domain-1 psid-offset 6
set services softwire softwire-concentrator map-t mapt-domain-1 psid-length 4
set services softwire softwire-concentrator map-t mapt-domain-1 mtu-v6 9192

set services softwire softwire-concentrator map-t mapt-domain-2 dmr-prefix 2001:db8:ffff:ffff::/64
set services softwire softwire-concentrator map-t mapt-domain-2 ipv4-prefix 100.99.99.0/24
set services softwire softwire-concentrator map-t mapt-domain-2 mapt-prefix 3001:db8:ffff::/48
set services softwire softwire-concentrator map-t mapt-domain-2 ea-bits-len 14
set services softwire softwire-concentrator map-t mapt-domain-2 psid-offset 6
set services softwire softwire-concentrator map-t mapt-domain-2 psid-length 6
set services softwire softwire-concentrator map-t mapt-domain-2 mtu-v6 9192

set services softwire rule sw-rule1 match-direction input
set services softwire rule sw-rule1 term t1 then map-t mapt-domain-1

set services softwire rule sw-rule2 match-direction input
set services softwire rule sw-rule2 term t1 then map-t mapt-domain-2
```

### View statistics 
```
root@map1# run show services inline softwire statistics mapt

 Service PIC Name                                    si-0/0/0

 Control Plane Statistics
     MAPT ICMPv6 translated to ICMPv4                   0
     MAPT ICMPv4 translated to ICMPv6                   0
     MAPT ICMPv4 discards                               0
     MAPT ICMPv6 discards                               0

 Data Plane Statistics (v6-to-v4)      Packets                 Bytes
     MAPT v6 translated to v4           11555                   658635
     MAPT v6 spoof drops                460                     26220
     MAPT v6 fragment drops             0                       0
     MAPT v6 unsupported drops          0                       0

 Data Plane Statistics (v4-to-v6)      Packets                 Bytes
     MAPT v4 translated to v6           0                       0
```

### View converted IPv4 address
Add a firewall filter in output direction on interface facing internet . Once Ipv6 routes are translated, they will exit over this 

#### Configuration
```
root@map1# show interfaces lt-0/0/10.12 | display set
set interfaces lt-0/0/10 unit 12 encapsulation ethernet
set interfaces lt-0/0/10 unit 12 peer-unit 13
set interfaces lt-0/0/10 unit 12 family inet filter output COUNT-INPUT
set interfaces lt-0/0/10 unit 12 family inet address 17.1.1.1/30

set firewall family inet filter COUNT-INPUT term 10 then count COUNT-INPUT
set firewall family inet filter COUNT-INPUT term 10 then log
set firewall family inet filter COUNT-INPUT term 10 then accep
```

#### Filter stats once converted
```
Time      Filter    Action Interface           Protocol        Src Addr                         Dest Addr
20:04:40  pfe       A      lo0.0               UDP             12.8.10.46                       99.99.99.49
20:04:39  pfe       A      lo0.0               UDP             12.8.10.46                       99.99.99.27
20:04:38  pfe       A      lo0.0               UDP             12.8.10.46                       99.99.99.41
20:04:37  pfe       A      lo0.0               UDP             12.8.10.46                       99.99.99.137
20:04:36  pfe       A      lo0.0               UDP             12.8.10.46                       99.99.99.172
```
