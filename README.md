# pcap-scrubber
The Pcap Scrubber - Scrub it clean before loading it into Wireshark

## Idea
When capturing traffic, we tend to see a lot of noise.
Pcap files can grow very large very quickly, especially when you don't know exactly what you are looking for, so your filters are coarse.
Trying to work efficiently with > 1G pcap files in Wireshark is next to impossible.

What if there was a tool that scrubs the pcap clean of all that noise and produces a much smaller file to load?

## What it does
The filtering mechanism of the tool is centered around the most common question:

*Why is it slow?*

The tool reads a large pcap file and analyzes every TCP connection for three things:
1. Wire latency
2. Server latency
3. Client latency

The tool will then present the median values for each type of latency, as well as a distribution
of the latency percentiles to the user. The user may then opt to filter only for connections of a certain latency percentile upwards.
(e.g. 85% of connections are faster than 100ms, so give me all connections of 100ms wire latency and slower)
The result of such a selection will be a smaller pcap file that contains only the packets belonging to the connections that match the
percentile criteria.
