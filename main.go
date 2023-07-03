/* Author: Aravind Prabhakar
   Version: 0.1
   Description: This app generates IPv6 packets with embedded v4 host addresses with permissible source ports
   to validate BR functionality. Creates IPv6 packets mimicing MAP-T CE functionality
*/

package main

import (
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

// to store packets
var pkt = make(map[string]string)
var pkts []map[string]string
var v6pkts [][]byte

// MAP-T definition.
type MaptDomain struct {
	DmrPrefix               string `yaml:"dmr-prefix"`
	MaptPrefix              string `yaml:"mapt-prefix"`
	EaBitsLen               int    `yaml:"eabits-len"`
	Ipv4Prefix              string `yaml:"ipv4-prefix"`
	PsidOffset              int    `yaml:"psid-offset"`
	PsidLen                 int    `yaml:"psid-len"`
	GenerateIncorrectRanges bool   `yaml:"generate-incorrect-ranges"`
	DestV4Ip                string `yaml:"dest-v4-ip"`
	PktIntf                 string `yaml:"pkt-intf"`
	Smac                    string `yaml:"smac"`
	Dmac                    string `yaml:"dmac"`
	PktType                 string `yaml:"pkt-type"`
}

/*
print input passed along with calculations
*/
func printInputs(dmrprefix string, maptprefix string, psidoffset int, psidlen int, v4sourceip string, v4destip string, portmodifierbits int, ceportrange int) {
	fmt.Println(" ====Generating RG traffic for below domain configs ===\n")
	fmt.Println("DMR prefix: ", dmrprefix)
	fmt.Println("BMR prefix: ", maptprefix)
	fmt.Println("PSID offset: ", psidoffset)
	fmt.Println("PSID len:	", psidlen)
	fmt.Println("Source v4 IP: ", v4sourceip)
	fmt.Println("Dest v4 IP: ", v4destip)
	fmt.Println("num modifier bits: ", portmodifierbits)
	fmt.Println("num of usable source ports per ce/PSID: ", ceportrange)
	fmt.Println("=======================================================\n")
}

/*
This converts binary string to IPv6 format
*/
func binaryToV6(binary string) string {
	// Pad the binary string with leading zeros to ensure it has 128 bits
	paddedbinarystring := fmt.Sprintf("%0128s", binary)

	// Convert the binary string to a byte slice
	bytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		b, err := strconv.ParseUint(paddedbinarystring[i*8:(i+1)*8], 2, 8)
		if err != nil {
			fmt.Println("Invalid binary string:", err)
		}
		bytes[i] = byte(b)
	}

	// Create an IPv6 address from the byte slice
	ip := net.IP(bytes)

	return ip.String()
}

/*
genrate interface

	| 16 bits|    32 bits     | 16 bits|
	+--------+----------------+--------+
	|   0    |  IPv4 address  |  PSID  |
	+--------+----------------+--------+
*/
func genInterfaceId(psid int, ipv4address netip.Addr) string {
	var iid []string

	// 16bits of zeros string slice
	//zb := make([]string, 2)
	iid = append(iid, fmt.Sprintf("%016b", 0))

	// IPv4 in binary string slice
	ip4, _ := ipv4address.MarshalBinary()
	for _, b := range ip4 {
		iid = append(iid, fmt.Sprintf("%08b", b))
	}

	/*Psid in binary string slice
	left pad with 0's to make length 16 */
	bpsid := strconv.FormatInt(int64(psid), 2)
	ppsid := fmt.Sprintf("%016s", bpsid)
	iid = append(iid, ppsid)

	return strings.Join(iid, "")
}

// Craft source IP to mimic MAP-T CE device.This returns hex value
func createSourceIp(ruleprefix string, psid int, ipv4address netip.Addr, eabitlen int) string {
	var sourceip []string

	iid := genInterfaceId(psid, ipv4address)

	splitmapt := strings.Split(ruleprefix, "/")
	rulesubnet, _ := strconv.Atoi(splitmapt[1])

	// parse rule prefix
	var maptprefix []string
	v6prefix, err := netip.ParsePrefix(ruleprefix)
	if err != nil {
		panic("unable to parse Ipv6 rule prefix")
	}
	ip6, _ := v6prefix.Addr().MarshalBinary()
	//for i := 0; i < 4; i++ {
	for _, b := range ip6 {
		maptprefix = append(maptprefix, fmt.Sprintf("%08b", b))
	}

	sourceip = append(sourceip, strings.Join(maptprefix, "")[:rulesubnet])

	//create eabits
	var eaval []string
	bpsid := strconv.FormatInt(int64(psid), 2)
	suffixlen := eabitlen - len(bpsid)
	suffixval := iid[16+(32-suffixlen) : 48]
	eaval = append(eaval, suffixval, bpsid)

	// calculate 0s to pad
	sbits := 64 - rulesubnet - eabitlen
	var sbitval string
	for i := 0; i < sbits; i++ {
		sbitval += "0"
	}

	sourceip = append(sourceip, eaval[0], eaval[1], sbitval, iid)
	sourceipjoined := strings.Join(sourceip, "")
	return binaryToV6(sourceipjoined)
}

/*
Craft destination IP to mimic MAP-T CE device. This returns hex value
<---------- 64 ------------>< 8 ><----- 32 -----><--- 24 --->
+--------------------------+----+---------------+-----------+
|        BR prefix         | u  | IPv4 address  |     0     |
+--------------------------+----+---------------+-----------+
*/

func createDestIp(dmrprefix string, destip netip.Addr) string {
	var bdestip []string
	var bdmrprefix []string

	splitmapt := strings.Split(dmrprefix, "/")
	dmrsubnet, _ := strconv.Atoi(splitmapt[1])
	v6prefix, err := netip.ParsePrefix(dmrprefix)
	if err != nil {
		panic("unable to parse Ipv6 rule prefix")
	}
	ip6, _ := v6prefix.Addr().MarshalBinary()
	for _, b := range ip6 {
		bdmrprefix = append(bdmrprefix, fmt.Sprintf("%08b", b))
	}
	bdestip = append(bdestip, strings.Join(bdmrprefix, "")[:dmrsubnet])

	// IPv4 in binary string slice
	var ipv4address []string
	ip4, _ := destip.MarshalBinary()
	for _, b := range ip4 {
		ipv4address = append(ipv4address, fmt.Sprintf("%08b", b))
	}
	jipv4 := strings.Join(ipv4address, "")

	// 8 bits of zeros
	u := fmt.Sprintf("%08b", 0)

	// 24 bits of zeros
	zeros := fmt.Sprintf("%024b", 0)

	bdestip = append(bdestip, u, jipv4, zeros)

	return binaryToV6(strings.Join(bdestip, ""))

}

/*
creates and returns all source ports based on PSIDs
*/
func createSourcePort(psidoffset int, portmodifierbits int, psidstartval int) []int {
	var (
		portlist  []int
		startport int
	)
	startport = int(math.Pow(2, float64(16-psidoffset))) + psidstartval
	for i := 1; i <= int(math.Pow(2, float64(psidoffset))); i++ {
		for j := 1; j <= int(math.Pow(2, float64(portmodifierbits))); j++ {
			portval := startport + j
			if portval <= 65536 {
				portlist = append(portlist, portval)
			} else {
				continue
			}
		}
		startport = startport + int(math.Pow(2, float64(16-psidoffset)))
	}
	return portlist
}

/*
Create startport range value for all psids based on psidlen and returns all the
ports computed into a map for each PSID
*/
func portsPerPsid(psidoffset int, psidlen int, portmodifierbits int) map[int][]int {
	var psidPortMap = make(map[int][]int)
	startval := 0
	for i := 0; i < int(math.Pow(2, float64(psidlen))); i++ {
		val := createSourcePort(psidoffset, portmodifierbits, startval)
		startval = startval + int(math.Pow(2, float64(16-psidoffset-psidlen)))
		psidPortMap[i] = val
	}
	return psidPortMap
}

/*
Generate random value between 2 numbers
*/
func generateRandom(min int, max int) int {
	return rand.Intn(max-min) + min
}

/*
Calculate number of subscribers the domain config can serve.
This will craft all the MAP-T CE source IP addresses for
various PSIDs
*/
func calculateRange(mapt MaptDomain) {
	var (
		eabitslen        int
		psidoffset       int
		psidlen          int
		portmodifierbits int
		ipv4suffixlen    int
		computedpfx      []netip.Addr
	)
	file, errs := os.Create("MAPT_CE_SIP_DIP.txt")
	if errs != nil {
		fmt.Println("failed to create file\n")
		return
	}
	defer file.Close()

	splitip := strings.Split(mapt.Ipv4Prefix, "/")
	subnetmask, _ := strconv.Atoi(splitip[1])
	ipv4suffixlen = 32 - subnetmask

	// handle eabitlen
	if mapt.EaBitsLen != 0 {
		eabitslen = mapt.EaBitsLen
	} else {
		panic("Ea bits not set. Please set this and retry!")
	}
	// handle offset
	if mapt.PsidOffset != 0 {
		if mapt.PsidOffset < 6 {
			fmt.Println("Warning! this may unblock 0-1023 ports. you may want to set offset to 6 which is default")
		} else {
			psidoffset = mapt.PsidOffset
		}
	} else {
		//set default to 6
		psidoffset = 6
	}
	// handle psid
	if mapt.PsidLen != 0 {
		if mapt.PsidLen != eabitslen-ipv4suffixlen {
			panic("Ea bit length mismatch. Length of Ea bits should be len of v4Suffix + len of PSID.\n validate EabitLen and PsidLen")
		} else {
			psidlen = mapt.PsidLen
		}
	} else {
		panic("Error: Psid len not defined. Please set this value and retry!")
	}

	// port modifier bits
	portmodifierbits = 16 - psidoffset - psidlen
	ceportrange := int((math.Pow(2, float64(portmodifierbits)) - 1) * (math.Pow(2, float64(psidoffset)) - 1))

	// print inputs before starting traffic
	printInputs(mapt.DmrPrefix, mapt.MaptPrefix, psidoffset, psidlen, mapt.Ipv4Prefix, mapt.DestV4Ip, portmodifierbits, ceportrange)

	// mapt customer ipv4 prefix
	prefix, err := netip.ParsePrefix(mapt.Ipv4Prefix)
	if err != nil {
		panic(err)
	}

	// destination prefix
	dpfx, err := netip.ParsePrefix(mapt.DestV4Ip)
	if err != nil {
		panic(err)
	}

	//compute possible destinations within provided subnet
	for daddr := dpfx.Addr(); dpfx.Contains(daddr); daddr = daddr.Next() {
		computedpfx = append(computedpfx, daddr)
	}

	if mapt.GenerateIncorrectRanges != true {
		usableSports := portsPerPsid(psidoffset, psidlen, portmodifierbits)
		// circulate through all customers IPs
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			// circulate through customers sharing the same prefix
			for psid := 0; psid <= int(math.Pow(2, float64(psidlen)))-1; psid++ {
				//pick a random port in the list of usable ports
				sportindex := generateRandom(0, len(usableSports[psid]))
				sport := usableSports[psid][sportindex]
				// pick a random destport
				dport := generateRandom(1024, 65535)
				sip := createSourceIp(mapt.MaptPrefix, psid, addr, eabitslen)
				// pick a random destination prefix from the computed list
				dipfx := generateRandom(0, len(computedpfx)-1)
				dip := createDestIp(mapt.DmrPrefix, computedpfx[dipfx])
				if len(os.Args) > 2 {
					if os.Args[2] == "save" {
						_, errs = file.WriteString("Source IP: " + sip + " Destionation IP: " + dip + " Source port: " + strconv.Itoa(sport) + " Destination Port: " + strconv.Itoa(dport) + "\n")
						if errs != nil {
							fmt.Println("Error!!! Failed to write results to file", errs)
						}
					} else if os.Args[2] == "generate" {
						pkt["sourceIp"] = sip
						pkt["destIp"] = dip
						pkt["sourcePort"] = strconv.Itoa(sport)
						pkt["destPort"] = strconv.Itoa(dport)
						pkts = append(pkts, pkt)
					} else {
						continue
					}
				} else {
					continue
				}
			}
		}
	} else {
		// generate with incorrect ports/ips to drop packets
		fmt.Println("WIP! please wait for v2.0 code")
	}
}

// createIpv6 Packet
func createV6Packet(pkt []map[string]string, smac string, dmac string, intf string, pkttype string) [][]byte {
	var (
		udp    *layers.UDP
		buffer gopacket.SerializeBuffer
		//icmp     *layers.ICMPv4
		smacadd []byte
		dmacadd []byte
		sipaddr []byte
		dipaddr []byte
		//protocol layers.IPProtocol
		payload gopacket.SerializableLayer
	)

	for i := 0; i < len(pkt); i++ {
		sipaddr = net.ParseIP(pkt[i]["sourceIp"])
		dipaddr = net.ParseIP(pkt[i]["destIp"])
		if pkttype == "icmp" {
			fmt.Println("currently not supported. Needs enhancement")
			//icmp = &layers.ICMPv6{TypeCode: layers.ICMPv6TypeCode(8)}
			//protocol = layers.IPProtocolICMPv6
		} else if pkttype == "udp" {
			source, _ := strconv.Atoi(pkt[i]["sourcePort"])
			dest, _ := strconv.Atoi(pkt[i]["destPort"])
			udp = &layers.UDP{SrcPort: layers.UDPPort(source), DstPort: layers.UDPPort(dest)}
			//protocol = layers.IPProtocolUDP
		} else {
			panic("source port and destination port missing. please add accordingly\n")
		}
		payload = gopacket.Payload("gopayload")
		smacadd, _ = net.ParseMAC(smac)
		dmacadd, _ = net.ParseMAC(dmac)
		if pkttype == "udp" {
			fmt.Println(" --> IP packet with udp \n")
			eth := &layers.Ethernet{SrcMAC: smacadd, DstMAC: dmacadd, EthernetType: 0x086DD}
			ip := &layers.IPv6{Version: 6, DstIP: dipaddr, SrcIP: sipaddr, NextHeader: layers.IPProtocolUDP, HopLimit: 64}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				return nil
			}
			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
				eth, ip, udp, payload); err != nil {
				return nil
			}
		}
		v6pkts = append(v6pkts, buffer.Bytes())
	}
	return v6pkts
}

// generate and send packet
func sendPacket(packet [][]byte, device string) {
	fmt.Println("sending packets...")
	var snapshotlen int32 = 65535
	var timeout = 30 * time.Second
	var promiscuous bool = false
	handle, err := pcap.OpenLive(device, snapshotlen, promiscuous, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	for i := 0; i < 10; i++ {
		err = handle.WritePacketData(packet[i])
		if err != nil {
			panic(err)
		}
	}
}

func main() {
	var mapt MaptDomain
	if len(os.Args) > 1 {
		if (os.Args[1] == "help") || (os.Args[1] == "--help") {
			fmt.Printf(`
	==============  MAP-T BR Verification Tool  ================
	Version: 1.0 

	Usage: ./mapt-br-verification <input.yaml> save
	
	This will craft packets within the defined ranges such that the BR would 
	translate. The idea is mimic a CPE device generating an IPv4 embedded Ipv6
	address towards the BR.
	
	when using the flag generate-incorrect-ranges. This will intentially craft a 
	packet outside of the range of PSID or use incorrect mapt-prefixes such that
	the BR fails translations.

	The argument save, will save the computed result into a file named MAPT_CE_SIP_DIP.txt
	============================================================
			`)
			fmt.Printf("\n")
		} else {
			rfile, err := ioutil.ReadFile(os.Args[1])
			if err != nil {
				fmt.Println(err)
			}
			err = yaml.Unmarshal(rfile, &mapt)
			if err != nil {
				fmt.Println(err)
			}
			if len(os.Args) > 2 {
				if os.Args[2] == "save" {
					calculateRange(mapt)
				} else if os.Args[2] == "generate" {
					calculateRange(mapt)
					pkt6 := createV6Packet(pkts, mapt.Smac, mapt.Dmac, mapt.PktIntf, mapt.PktType)
					sendPacket(pkt6, mapt.PktIntf)
				} else {
					fmt.Println("\nError!!! Incorrect input, not computing. check usage under help")
				}
			}
		}
	} else {
		fmt.Println("Missing or incorrect argument input file. Please refer to help function \n")
	}
}
