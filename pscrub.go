package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
)

const DefaultConversationLength = 10

type Statistics struct {
	histogram    map[time.Duration]int
	percentile10 time.Duration
	percentile25 time.Duration
	percentile50 time.Duration
	percentile75 time.Duration
	percentile90 time.Duration
	percentile95 time.Duration
	percentile99 time.Duration
	average      time.Duration
	median       time.Duration
	slowest      time.Duration
	fastest      time.Duration
}

// A ShallowPacket contains only IP and TCP metadata relevant for statistics.
type ShallowPacket struct {
	metadata *gopacket.PacketMetadata
	tcp      *layers.TCP
	ip       *layers.IPv4
}

// A Conversation represents two stations talking using TCP.
// It consists of packet metadata as well as latency statistics.
type Conversation struct {
	packets        []*ShallowPacket // This contains everything we need for statistical analysis
	networkLatency *Statistics      // Network latency = Empty ACK from remote (no L7 data)
	localLatency   *Statistics      // Local latency   = L7 data from client (local IP, random high port)
	remoteLatency  *Statistics      // Remote latency  = L7 data from server (non-local IP, well-known port)
}

// A Capture represents the entirety of all TCP conversations.
// It consists of conversation metadata as well as latency statistics.
type Capture struct {
	conversations  map[uint64]*Conversation // This contains all TCP conversation metadata
	networkLatency *Statistics              // Based on median network latency over all conversations
	localLatency   *Statistics              // Based on median local latency over all conversations
	remoteLatency  *Statistics              // Based on median remote latency over all conversations
}

func NewStatistics() *Statistics {
	statistics := &Statistics{
		histogram:    make(map[time.Duration]int),
		percentile10: 0,
		percentile25: 0,
		percentile50: 0,
		percentile75: 0,
		percentile90: 0,
		percentile95: 0,
		percentile99: 0,
		average:      0,
		median:       0,
		slowest:      0,
		fastest:      0,
	}

	return statistics
}

func NewShallowPacket(metaData *gopacket.PacketMetadata, tcp *layers.TCP, ip *layers.IPv4) *ShallowPacket {
	shallowsPacket := &ShallowPacket{
		metadata: metaData,
		tcp:      tcp,
		ip:       ip,
	}

	return shallowsPacket
}

func NewConversation() *Conversation {
	conversation := &Conversation{
		packets:        make([]*ShallowPacket, DefaultConversationLength),
		networkLatency: NewStatistics(),
		localLatency:   NewStatistics(),
		remoteLatency:  NewStatistics(),
	}

	return conversation
}

func NewCapture() *Capture {
	capture := &Capture{
		conversations:  make(map[uint64]*Conversation),
		networkLatency: NewStatistics(),
		localLatency:   NewStatistics(),
		remoteLatency:  NewStatistics(),
	}

	return capture
}

func main() {
	handle, err := pcap.OpenOffline("example.pcap")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	capture := NewCapture()

	// 1. Load packet metadata
	for packet := range packetSource.Packets() {
		if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
			flow := tcp.TransportFlow()
			key := flow.FastHash()

			if ipv4, ok := packet.NetworkLayer().(*layers.IPv4); ok {
				shallow := NewShallowPacket(packet.Metadata(), tcp, ipv4)

				conversation := capture.conversations[key]
				if conversation == nil {
					conversation = NewConversation()
					capture.conversations[key] = conversation
				}

				conversation.packets = append(conversation.packets, shallow)
			}
		}
	}

	fmt.Println(len(capture.conversations))
}
