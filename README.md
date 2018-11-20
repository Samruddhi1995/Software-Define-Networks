# Software-Define-Networks
Mininet, RYU, OpenFLow v-1.3

Topology 



Following Rules are implemented

1 Everything follows shortest path
2 When there are two shortest paths available
  	ICMP and TCP packets take the lower/left path
    S1-S2-S3 and S2-S3-S4
    UDP packets take the upper/right path
    S1-S4-S3 and S2-S1-S4
3 H2 and H4 cannot have HTTP traffic (TCP with port:80)
    New connections are dropped with a TCP RST sent back to H1 or H3
    To be more specific, when the first TCP packet (SYN) arrives S1 or S3, forwarded it to controller, controller then create a RST packet and send it back to the host.
4 H1 and H4 cannot have UDP traffic
    simply drop packets at switches
