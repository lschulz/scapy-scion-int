"""
SCION Control Message Protocol
https://scion.docs.anapaya.net/en/latest/protocols/scmp.html
"""

from scapy.fields import (ByteEnumField, ByteField, MultipleTypeField,
                          PacketField, ShortField, XShortField, XStrField)
from scapy.packet import Packet, bind_layers

from layers.scion import SCION, EndToEndExt, HopByHopExt, ProtocolNumbers


SCMPTypes = {
    # Error Messages
    1: "Destination Unreachable",
    2: "Packet Too Big",
    4: "Parameter Problem",
    5: "External Interface Down",
    6: "Internal Connectivity Down",
    100: "Experimental Error 1",
    101: "Experimental Error 2",
    # Informational Messages
    128: "Echo Request",
    129: "Echo Reply",
    130: "Traceroute Request",
    131: "Traceroute Reply",
    200: "Experimental Info 1",
    201: "Experimental Info 2",
}

SCMPTypeNumbers = {
    # Error Messages
    "Destination Unreachable": 1,
    "Packet Too Big": 2,
    "Parameter Problem": 4,
    "External Interface Down": 5,
    "Internal Connectivity Down": 6,
    "Experimental Error 1": 100,
    "Experimental Error 2": 101,
    # Informational Messages
    "Echo Request": 128,
    "Echo Reply": 129,
    "Traceroute Request": 130,
    "Traceroute Reply": 131,
    "Experimental Info 1": 200,
    "Experimental Info 2": 201,
}


class EchoRequest(Packet):
    """SCMP Echo Request"""

    name = "Echo Request"

    fields_desc = [
        ShortField("Identifier", default=0),
        ShortField("Sequence Number", default=0),
        XStrField("Data", default=b"")
    ]


class EchoReply(Packet):
    """SCMP Echo Reply"""

    name = "Echo Reply"

    fields_desc = [
        ShortField("Identifier", default=0),
        ShortField("Sequence Number", default=0),
        XStrField("Data", default=b"")
    ]


class SCMP(Packet):
    """SCION Control Message Protocol"""

    name = "SCMP"

    fields_desc = [
        ByteEnumField("Type", default="Echo Request", enum=SCMPTypes),
        ByteField("Code", default=0),
        XShortField("Checksum", default=None), # Checksum is computed in SCION layer
        MultipleTypeField([
            (PacketField("Message", default=EchoRequest(), pkt_cls=EchoRequest),
                lambda pkt: pkt.Type == SCMPTypeNumbers['Echo Request']),
            (PacketField("Message", default=EchoReply(), pkt_cls=EchoReply),
                lambda pkt: pkt.Type == SCMPTypeNumbers['Echo Reply'])],
            XStrField("Message", default=None)
        )
    ]


bind_layers(SCION, SCMP, NextHdr=ProtocolNumbers['SCMP'])
bind_layers(HopByHopExt, SCMP, NextHdr=ProtocolNumbers['SCMP'])
bind_layers(EndToEndExt, SCMP, NextHdr=ProtocolNumbers['SCMP'])
