// gop0f cli is a utility for accessing the p0f api from the command-line
package main

import (
	"flag"
	"fmt"
	"github.com/cure/gop0f"
	"net/netip"
	"os"
)

var (
	flagUnixsock = flag.String("s", "/var/run/p0f.sock", "Location of the p0f unix socket.")
	flagOutput   = flag.String("o", "grep", "Output in grep|json format.")
	flagQuery    = flag.String("q", "", "IP to query for.")
	flagVersion  = flag.Bool("v", false, "Display version and exit.")
	VERSION      string // Set by GOXC
)

func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Printf("p0f-cli %s\n", VERSION)
		os.Exit(0)
	}

	p0fclient, err := gop0f.New(*flagUnixsock)
	if err != nil {
		panic(err)
	}

	ip, err := netip.ParseAddr(*flagQuery)
	if err != nil {
		panic("IP invalid")
	}

	resp, err := p0fclient.Query(ip)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}
