Tools for Examining SCION Traffic
=================================

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
