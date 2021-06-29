"""
Bidirectional Forwarding Detection (BFD) on top of SCION
https://scion.docs.anapaya.net/en/latest/protocols/bfd.html
"""

from scapy.fields import (BitEnumField, BitField, ByteField, FieldLenField,
                          FlagsField, IntField, XStrLenField)
from scapy.packet import Packet, bind_layers

from layers.scion import SCION, EndToEndExt, HopByHopExt, ProtocolNumbers


class BFD(Packet):
    """Bidirectional Forwarding Detection (RFC 5880, RFC 5881)"""

    name = "BFD"

    fields_desc = [
        BitField("Version", default=1, size=3),
        BitEnumField("Diagnostic", default=0, size=5, enum={
            0: "No Diagnostic",
            1: "Control Detection Time Expired",
            2: "Echo Function Failed",
            3: "Neighbor Signaled Session Down",
            4: "Forwarding Plane Reset",
            5: "Path Down",
            6: "Concatenated Path Down",
            7: "Administratively Down",
            8: "Reverse Concatenated Path Down"
        }),
        BitEnumField("State", default=3, size=2, enum={
            0: "AdminDown",
            1: "Down",
            2: "Init",
            3: "Up"
        }),
        FlagsField("Flags", default=0, size=6, names="MDACFP"),
        ByteField("Detect Multiplier", default=1),
        FieldLenField("Length", default=None, fmt="B",
            length_of="Authentication",
            adjust=lambda pkt, x: x - 24),
        IntField("My Discriminator", default=None),
        IntField("Your Deiscriminator", default=None),
        IntField("Desired Min TX Interval", default=None),
        IntField("Required Min TX Interval", default=None),
        IntField("Required Min Echo RX Interval", default=None),
        XStrLenField("Authentication", default="", length_from=lambda pkt: pkt.Length - 24)
    ]


bind_layers(SCION, BFD, NextHdr=ProtocolNumbers['BFD'])
bind_layers(HopByHopExt, BFD, NextHdr=ProtocolNumbers['BFD'])
bind_layers(EndToEndExt, BFD, NextHdr=ProtocolNumbers['BFD'])
