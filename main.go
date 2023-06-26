/* Author: Aravind Prabhakar
   Version: 0.1
   Description: MAP-T BR verification. This script generates
   IPv6 packets with embedded v4 host addresses.
*/

package main

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"

	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/pcap"
	//"github.com/akamensky/argparse"
	"os"
	//"time"
)

// MAP-T definition
type MaptDomain struct {
	DmrPrefix               string `yaml:"dmr-prefix"`
	MaptPrefix              string `yaml:"mapt-prefix"`
	EaBitsLen               string `yaml:"eabits-len"`
	Ipv4Prefix              string `yaml:"ipv4-prefix"`
	PsidOffset              string `yaml:"psid-offset"`
	PsidLen                 string `yaml:"psid-len"`
	GenerateIncorrectRanges string `yaml:"generate-incorrect-ranges"`
}

// Calculate number of subscribers the domain config can server
/*func calculateMaxSubscribers(mapt MaptDomain, numcustomers int64) {
	// split after /
	v4suffixlen :=
	// 32 - v4suffixlen = prefixlen
	v4prefix :=
	//2^availablev4
	availablev4 :=
	psid


}*/

// generate and send packet
/*func generatePacket(v4Source, sourcePort, v4Dest, destPort, proto) {
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
			fmt.Println(mapt)
		}
	} else {
		fmt.Println("Missing or incorrect argument input file. Please refer to help function \n")
	}
}
