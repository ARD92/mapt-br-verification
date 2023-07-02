# MAP-T BR Verification Tool

This is a tool to validate MAP-T Border relay functionality. This crafts packets based on input provided such as PSID offset, MAP-T Rule prefix, DMR prefix. The Source IP would be that of a MAP-T CE device such as an RG along with defined allowable ports. To simulate spoof errors, use the flag genrateIncorrectRanges.


## Input file 
```
---
dmr-prefix : "2001:db8:1111:2222::/64"
mapt-prefix: "3010:1122::/32"
eabits-len: 12
ipv4-prefix: "12.8.10.0/24"
psid-offset: 6
psid-len : 4
#value set to "true" would craft packets that intentionally fall out of the permissible port ranges and hence BR should not translate it.
generate-incorrect-ranges: false
# This would pick a destination address from the subnet block and randomly generate a packet towards it.
dest-v4-ip : "99.99.99.0/24"
```

## Usage

```
./mapt-br-verification help

	==============  MAP-T BR Verification Tool  ================

	Usage: ./mapt-br-verification <input.yaml>

	This will craft packets within the defined ranges such that the BR would
	translate. The idea is mimic a CPE device generating an IPv4 embedded Ipv6
	address towards the BR.

	when using the flag generate-incorrect-ranges. This will intentially craft a
	packet outside of the range of PSID or use incorrect mapt-prefixes such that
	the BR fails translations.

	============================================================
```


