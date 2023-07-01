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
	"strconv"
	"strings"

	"net"

	"net/netip"

	"gopkg.in/yaml.v3"

	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/pcap"
	"os"
)

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
genrate interface

	| 16 bits|    32 bits     | 16 bits|
	+--------+----------------+--------+
	|   0    |  IPv4 address  |  PSID  |
	+--------+----------------+--------+
*/
func genInterfaceId(psid int, ipv4add net.IP) {
	fmt.Println("generating interface ID")
	//var zeros uint16
	//var ipv4 uint32
	//var psid uint16
}

// Craft source IP to mimic MAP-T CE device.This returns hex value
func createSourceIp(ruleprefix string, psid int, sport int, ipv4address netip.Addr) {
	fmt.Println(ipv4address)
}

/*
// Craft destination IP to mimic MAP-T CE device. This returns hex value
func createDestIp(mapt maptDomain) {
	return destIp
}
*/

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
	)

	splitip := strings.Split(mapt.Ipv4Prefix, "/")
	subnetmask, _ := strconv.Atoi(splitip[1])
	ipv4suffixlen = 32 - subnetmask

	/*Ipprefix parsing
	parsePrefix, err := netaddr.ParseIP(splitip[0])
	if err != nil {
		panic("Unable to parse IPv4 prefix")
	}*/

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

	prefix, err := netip.ParsePrefix(mapt.Ipv4Prefix)
	if err != nil {
		panic(err)
	}
	if mapt.GenerateIncorrectRanges != true {
		usableSports := portsPerPsid(psidoffset, psidlen, portmodifierbits)
		// circulate through all customers IPs
		//for host := 1; host <= int(math.Pow(2, float64(ipv4suffixlen)))-2; host++ {
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			// circulate through customers sharing the same prefix
			for psid := 0; psid <= int(math.Pow(2, float64(psidlen)))-1; psid++ {
				//pick a random port in the list of usable ports
				sportindex := generateRandom(0, len(usableSports[psid]))
				sport := usableSports[psid][sportindex]
				// pick a random destport
				//dport := generateRandom(1024, 65535)
				createSourceIp(mapt.MaptPrefix, psid, sport, addr)
			}
		}
	} else {
		// generate with incorrect ports/ips to drop packets
		fmt.Println("WIP! please wait for v2.0 code")
	}

}

// generate and send packet
/*func sendPacket(v4Source, sourcePort, v4Dest, destPort, proto) {
}*/

func main() {
	var mapt MaptDomain
	if len(os.Args) > 1 {
		if (os.Args[1] == "help") || (os.Args[1] == "--help") {
			fmt.Printf(`
	==============  MAP-T BR Verification Tool  ================
				
	Usage: ./mapt-br-verification <input.yaml>
	
	This will craft packets within the defined ranges such that the BR would 
	translate. The idea is mimic a CPE device generating an IPv4 embedded Ipv6
	address towards the BR.
	
	when using the flag generate-incorrect-ranges. This will intentially craft a 
	packet outside of the range of PSID or use incorrect mapt-prefixes such that
	the BR fails translations.
	
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
			calculateRange(mapt)
		}
	} else {
		fmt.Println("Missing or incorrect argument input file. Please refer to help function \n")
	}
}
