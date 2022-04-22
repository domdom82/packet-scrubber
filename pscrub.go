package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	flows := map[uint64][]gopacket.Packet{}

	handle, err := pcap.OpenOffline("example.pcap")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
			flow := tcp.TransportFlow()
			key := flow.FastHash()
			flows[key] = append(flows[key], packet)
		}
	}

	fmt.Printf("Found %d TCP flows in the pcap!\n", len(flows))
}
