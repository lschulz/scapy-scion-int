#! /usr/bin/env python3

from scapy.all import *
from scapy_scion.layers.scion import *
from scapy_scion.layers.scmp import *
from scapy_scion.layers.bfd import *
from scapy_scion.layers.idint import *


# Additional layers bindings
# See https://github.com/scionproto/scion/blob/master/tools/wireshark/scion.lua
for port in range(30000, 32000):
    bind_bottom_up(UDP, SCION, dport=port)
    bind_bottom_up(UDP, SCION, sport=port)
for port in range(40000, 40050):
    bind_bottom_up(UDP, SCION, dport=port)
    bind_bottom_up(UDP, SCION, sport=port)
for port in range(50000, 50050):
    bind_bottom_up(UDP, SCION, dport=port)
    bind_bottom_up(UDP, SCION, sport=port)


if __name__ == "__main__":
    interact(mydict=globals())
