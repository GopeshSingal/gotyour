package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	device := "wlp15s0"
	snapshotLen := int32(1024)
	promiscuous := true
	timeout := 30 * time.Second

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	pkt_src := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Listening for packets...")

	for pkt := range pkt_src.Packets() {
		networkLayer := pkt.NetworkLayer()
		if networkLayer != nil {
			fmt.Printf("Source: %s -> Dest: %s\n", networkLayer.NetworkFlow().Src(), networkLayer.NetworkFlow().Dst())
		}
	}
}
