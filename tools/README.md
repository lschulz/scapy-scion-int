Tools
=====

Custom Scapy tools for examining SCION traffic and services.

Local SCION Packet Tracing
--------------------------
[local_trace.py](./local_trace.py)

Print the changes occurring in the SCION packet header while a packet traverses border routers on
its path. Only works with local topologies where every packet passes through the loopback interface.

Example:
```bash
# Create and run a local SCION topology
cd $scion_src
./scion.sh topology -c $this_repo/tools/topo/linear.yaml
./scion.sh run
# Observe how the packet is modified by the border routers
cd $this_repo
sudo ./local_trace.py -s $scion_src
```

Output:
```
### Ping destination AS
Resolved local address:
  127.0.0.1
Using path:
  Hops: [1-ff00:0:3 1>2 1-ff00:0:2 1>2 1-ff00:0:1 1>1 2-ff00:0:4 2>1 3-ff00:0:5 2>1 3-ff00:0:6 2>1 3-ff00:0:7] MTU: 1280 NextHop: 127.0.0.33:31014

PING 3-ff00:0:7,127.0.0.1:0 pld=0B scion_pkt=180B
188 bytes from 3-ff00:0:7,127.0.0.1: scmp_seq=0 time=1.455ms

--- 3-ff00:0:7,127.0.0.1 statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 102.474ms
### Trace probe packet
Sending probe to 127.0.0.33:31014:  SCION / UDP 6500 > 6500 / PROBEHDR
Hop Source           > br1-ff00_0_3-1#i |
Hop br1-ff00_0_3-1#1 > br1-ff00_0_2-2#2 | CurrHF  = 1
Hop br1-ff00_0_2-2#i > br1-ff00_0_2-1#i | InfoFields[0]/SegID= 42889
Hop br1-ff00_0_2-1#1 > br1-ff00_0_1-2#2 | CurrHF  = 2
Hop br1-ff00_0_1-2#i > br1-ff00_0_1-1#i | CurrINF = 1 CurrHF  = 3 InfoFields[0]/SegID= 40275
Hop br1-ff00_0_1-1#1 > br2-ff00_0_4-1#1 | CurrHF  = 4
Hop br2-ff00_0_4-1#i > br2-ff00_0_4-2#i | InfoFields[1]/SegID= 22540
Hop br2-ff00_0_4-2#2 > br3-ff00_0_5-1#1 | CurrHF  = 5
Hop br3-ff00_0_5-1#i > br3-ff00_0_5-2#i | CurrINF = 2 CurrHF  = 6 InfoFields[1]/SegID= 27025
Hop br3-ff00_0_5-2#2 > br3-ff00_0_6-1#1 | CurrHF  = 7 InfoFields[2]/SegID= 59853
Hop br3-ff00_0_6-1#i > br3-ff00_0_6-2#i |
Hop br3-ff00_0_6-2#2 > br3-ff00_0_7-1#1 | CurrHF  = 8 InfoFields[2]/SegID= 13333
Hop br3-ff00_0_7-1#i > Destination      |
```

SCION Border Router STUN Scanner
--------------------------------
[stunscanner.py](./stunscanner.py)

Scans a range of IPs and ports for possible SCION border routers by sending a STUN binding request.

Example:
```bash
$ stunscanner.py 127.0.0.0/24 31000-31020
127.0.0.9 31002 open (xip=127.0.0.1, xport=61382)
127.0.0.10 31004 open (xip=127.0.0.1, xport=37092)
127.0.0.17 31008 open (xip=127.0.0.1, xport=54885)
Valid: 3, Open: 0, Closed: 5371, Filtered: 2
```

Usage:
```
usage: stunscanner [-h] [-a] [-s SPORT] [-t TIMEOUT] [-f] [-F] target [port]

Scans a range of IPs and ports for possible SCION border routers by sending a STUN binding request.

positional arguments:
  target                Target address. May be a single IP address (127.0.0.1), a subnet (127.0.0.0/24), or a range of addresses (127.0.0.1-127.0.0.10).
  port                  Target ports. May be a single port (3478), a port range (3478-3479) or a list of ports (3478,3479,31000-310010). If no other ports
                        are given, the default STUN port 3478 is probed.

options:
  -h, --help            show this help message and exit
  -a, --all             Print all scanned ports even if filtered or closed.
  -s SPORT, --sport SPORT
                        Source port of request packets. By default random ports above 32768, changing with every packet.
  -t TIMEOUT, --timeout TIMEOUT
                        Receive timeout after the last packet has been sent.
  -f, --no-fingerprint  Do not include the FINGERPRINT attribute in the binding request. Border routers do not normally answer such packets, but generic
                        STUN servers do.
  -F, --wrong-fingerprint
                        Include the FINGERPRINT attribute with an incorrect CRC32. Border routers do not normally answer such packets, but other STUN
                        servers might.
```
