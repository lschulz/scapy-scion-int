"""
Bidirectional Forwarding Detection (BFD) on top of SCION
https://docs.scion.org/en/latest/protocols/bfd.html
"""

from scapy.fields import (
    BitEnumField, BitField, ByteField, FieldLenField, FlagsField, IntField,
    XStrLenField
)
from scapy.packet import Packet, bind_layers

from .scion import SCION, EndToEndExt, HopByHopExt, SCION_PROTO_NUMBERS


class BFD(Packet):
    """Bidirectional Forwarding Detection (RFC 5880, RFC 5881)"""

    name = "BFD"

    fields_desc = [
        BitField("version", default=1, size=3),
        BitEnumField("diagnostic", default=0, size=5, enum={
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
        BitEnumField("state", default=3, size=2, enum={
            0: "AdminDown",
            1: "Down",
            2: "Init",
            3: "Up"
        }),
        FlagsField("flags", default=0, size=6, names="MDACFP"),
        ByteField("detect_multiplier", default=1),
        FieldLenField("length", default=None, fmt="B",
            length_of="authentication",
            adjust=lambda pkt, x: x - 24),
        IntField("my_discriminator", default=None),
        IntField("your_discriminator", default=None),
        IntField("desired_min_tx_interval", default=None),
        IntField("required_min_tx_interval", default=None),
        IntField("required_min_echo_rx_interval", default=None),
        XStrLenField("authentication", default="", length_from=lambda pkt: pkt.length - 24)
    ]


bind_layers(SCION, BFD, nh=SCION_PROTO_NUMBERS['BFD'])
bind_layers(HopByHopExt, BFD, nh=SCION_PROTO_NUMBERS['BFD'])
bind_layers(EndToEndExt, BFD, nh=SCION_PROTO_NUMBERS['BFD'])
