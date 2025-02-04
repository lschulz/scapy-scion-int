SCION and In-band Network Telemetry Layers for Scapy
====================================================

[Scapy](https://scapy.net/) is an interactive packet manipulation program/library for Python. This
repository contains Scapy packet header definitions ("layers") for [SCION](https://www.scion-architecture.net/)
and In-band Network Telemetry (INT) on top of SCION. Just start Scapy by running
`sudo ./scapy_scion.py` and the new headers are available at the interactive command line.

Supported headers:
- SCION (with path types EmptyPath, SCION, and OneHopPath)
- SCION Hop-by-Hop and End-to-End Options Header
- SCMP (only Echo Request and Reply)
- BFD over SCION
- INT-MD over UDP
- Inter-domain INT for SCION

Some SCION tools built with Scapy are available in [tools](/tools).

### Dependencies
- Python >= 3.10
- [Scapy](https://scapy.net/) (2.5.0)
- Additional Python packages:
    - cryptography (39.0.0)

### Install as a local package
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[extras]
```

### Run Unit Tests
```bash
python3 -m unittest
```

Detecting SCION as UDP Payload
------------------------------
SCION headers are encapsulated in UDP. Since SCION does not use a well-known set of UDP ports, the
presence of SCION is detected heuristically using Scapy's `guess_payload_class()` method. Since
`guess_payload_class()` must be overridden in the layer above SCION (UDP), we provide a replacement
for `scapy.layers.inet.UDP` in `scapy_scion.layers.scion.UDP`. `scion.UDP` is a subclass of
`inet.UDP` that tries to decode its payload as SCION. If unsuccessful the default guessing mechanism
is invoked. In addition to the heuristic, the [default port ranges][1] of the SCION open-source
stack are bound to the SCION layer.

[1]: https://github.com/scionproto/scion/wiki/Default-port-ranges

**Importing `scapy_scion.layers.scion` breaks the association of IP/IPv6 with `inet.UDP` and
replaces it with `scion.UDP`. Make sure to import `scion.UDP` insted of `inet.UDP` when using this
library.**

Getting Started: Craft and Send a SCION Packet
----------------------------------------------
1. Ping the target AS.

Replace `127.0.0.27:30255` with the address of your SCION daemon and the destination AS with the AS
you want to send packets to.
```
bin/scion ping --sciond 127.0.0.27:30255 2-ff00:0:211,127.0.0.1
```

2. Launch Scapy in a second terminal and capture one of the echo requests.

Replace IP `127.0.0.25` and port `31014` with the internal address of your border router.
```
sudo ./scapy_scion.py
bind_layers(UDP, SCION, dport=31014)
bind_layers(UDP, SCION, sport=31014)
pkts = sniff(iface="lo",
    filter="host 127.0.0.25 and port 31014",
    lfilter=lambda pkt: pkt.haslayer(SCMP) and pkt[SCMP].Type==128,
    prn=lambda pkt: pkt.summary(), count=1)
```

3. Extract the IP/UDP underlay and the SCION header.
```
p = pkts[0][IP]
p[SCION].remove_payload()
del p[IP].len
del p[IP].chksum
del p[UDP].len
del p[UDP].chksum
del p[SCION].NextHdr
del p[SCION].HdrLen
del p[SCION].PayloadLen
```

4. Build a new packet (e.g., a new echo request) and send it.

Changing `conf.L3Socket` to `L3RawSocket` is required in order to send packets to local
applications.
Refer to this [FAQ](https://scapy.readthedocs.io/en/latest/troubleshooting.html#i-can-t-ping-127-0-0-1-scapy-does-not-work-with-127-0-0-1-or-on-the-loopback-interface).
```
req = p/SCMP(Message=EchoRequest(Identifier=0xabcd, Data=b"Hello!"))
req[SCION].DstHostAddr = "127.0.0.2"
conf.L3socket = L3RawSocket
resp = sr1(req, iface="lo", timeout=1)
resp.show()
```
