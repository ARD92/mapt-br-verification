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

type MaptDomain struct {
	DmrPrefix	string `yaml:"dmr-prefix"`
	MaptPrefix	string `yaml:"mapt-prefix"`
	EaBitsLen	string `yaml:"eabits-len"`
	Ipv4Prefix	string `yaml:"ipv4-prefix"`
	PsidOffset	string `yaml:"psid-offset"`
	PsidLen		string `yaml:"psid-len"`
}

func main() {
	var mapt MaptDomain
	if len(os.Args) > 1 {
		rfile, err := ioutil.ReadFile(os.Args[1])
		if err != nil {
			fmt.Println(err)
		}
		err = yaml.Unmarshal(rfile, &mapt)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		fmt.Println("Missing argument input file\n")
	}
	fmt.Println(mapt)
}


