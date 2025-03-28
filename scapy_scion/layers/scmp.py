"""
SCION Control Message Protocol
https://docs.scion.org/en/latest/protocols/scmp.html
"""

from typing import Optional, Tuple

from scapy.fields import (
    ByteField, IntField, LongField, MultipleTypeField,PacketField, ShortField,
    XShortField
)
from scapy.packet import Packet, bind_layers

from ..fields import AsnField
from .scion import SCION, EndToEndExt, HopByHopExt, SCION_PROTO_NUMBERS


class _ScmpMessage(Packet):
    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class ScmpUnreachable(_ScmpMessage):
    """SCMP Destination Unreachable"""

    name = "Destination Unreachable"

    @property
    def type(self):
        return 1

    codes = {
        0: "no route to destination",
        1: "communication administratively denied",
        2: "beyond scope of source address",
        3: "address unreachable",
        4: "port unreachable",
        5: "source address failed ingress/egress policy",
        6: "reject route to destination",
    }

    fields_desc = [
        IntField("unused", default=0)
    ]


class ScmpPacketTooBig(_ScmpMessage):
    """SCMP Packet Too Big"""

    name = "Packet Too Big"

    @property
    def type(self):
        return 2

    fields_desc = [
        ShortField("reserved", default=0),
        ShortField("mtu", default=1280)
    ]


class ScmpParameterProblem(_ScmpMessage):
    """SCMP Parameter Problem"""

    name = "Parameter Problem"

    @property
    def type(self):
        return 4

    codes = {
        0: "erroneous header field",
        1: "unknown header field",
        16: "invalid common header",
        17: "unknown SCION version",
        18: "FlowID required",
        19: "invalid packet size",
        20: "unknown path type",
        21: "unknown address format",
        32: "invalid address header",
        33: "invalid source address",
        34: "invalid destination address",
        35: "non-local delivery",
        48: "invalid path",
        49: "unknown hop field cons ingress interface",
        50: "unknown hop field cons egress interface",
        51: "invalid hop field MAC",
        52: "path expired",
        53: "invalid segment change",
        64: "invalid extension header",
        65: "unknown hop-by-hop option",
        66: "unknown end-to-end option",
    }

    fields_desc = [
        ShortField("reserved", default=0),
        ShortField("pointer", default=0)
    ]


class ScmpExternalInterfaceDown(_ScmpMessage):
    """SCMP External Interface Down"""

    name = "External Interface Down"

    @property
    def type(self):
        return 5

    fields_desc = [
        ShortField("isd", default=0),
        AsnField("asn", default="0"),
        LongField("iface", default=0)
    ]


class ScmpInternalConnectivityDown(_ScmpMessage):
    """SCMP Internal Connectivity Down"""

    name = "Internal Connectivity Down"

    @property
    def type(self):
        return 6

    fields_desc = [
        ShortField("isd", default=0),
        AsnField("asn", default="0"),
        LongField("ingress", default=0),
        LongField("egress", default=0)
    ]


class ScmpEchoRequest(_ScmpMessage):
    """SCMP Echo Request"""

    name = "Echo Request"

    @property
    def type(self):
        return 128

    fields_desc = [
        ShortField("id", default=0),
        ShortField("seq", default=0)
    ]


class ScmpEchoReply(_ScmpMessage):
    """SCMP Echo Reply"""

    name = "Echo Reply"

    @property
    def type(self):
        return 129

    fields_desc = [
        ShortField("id", default=0),
        ShortField("seq", default=0)
    ]


class ScmpTracerouteRequest(_ScmpMessage):
    """SCMP Traceroute Request"""

    name = "Traceroute Request"

    @property
    def type(self):
        return 130

    fields_desc = [
        ShortField("id", default=0),
        ShortField("seq", default=0),
        ShortField("isd", default=0),
        AsnField("asn", default="0"),
        LongField("iface", default=0),
    ]


class ScmpTracerouteReply(_ScmpMessage):
    """SCMP Traceroute Reply"""

    name = "Traceroute Reply"

    @property
    def type(self):
        return 131

    fields_desc = [
        ShortField("id", default=0),
        ShortField("seq", default=0),
        ShortField("isd", default=0),
        AsnField("asn", default="0"),
        LongField("iface", default=0),
    ]


class SCMP(Packet):
    """SCION Control Message Protocol"""

    name = "SCMP"

    # Error Messages
    TypeDestinationUnreachable = 1
    TypePacketTooBig = 2
    TypeParameterProblem = 4
    TypeExternalInterfaceDown = 5
    TypeInternalConnectivityDown = 6
    TypeExperimentalError = 100
    TypeExperimentalError2 = 101

    # Informational Messages
    TypeEchoRequest = 128
    TypeEchoReply = 129
    TypeTracerouteRequest = 130
    TypeTracerouteReply = 131
    TypeExperimentalInfo = 200
    TypeExperimentalInfo = 201

    fields_desc = [
        ByteField("type", default=None),
        ByteField("code", default=0),
        XShortField("chksum", default=None), # Checksum is computed in SCION layer
        MultipleTypeField([
            (PacketField("message", default=ScmpUnreachable(), pkt_cls=ScmpUnreachable),
                lambda pkt: pkt.type == SCMP.TypeDestinationUnreachable),
            (PacketField("message", default=ScmpPacketTooBig(), pkt_cls=ScmpPacketTooBig),
                lambda pkt: pkt.type == SCMP.TypePacketTooBig),
            (PacketField("message", default=ScmpParameterProblem(), pkt_cls=ScmpParameterProblem),
                lambda pkt: pkt.type == SCMP.TypeParameterProblem),
            (PacketField("message", default=ScmpExternalInterfaceDown(), pkt_cls=ScmpExternalInterfaceDown),
                lambda pkt: pkt.type == SCMP.TypeExternalInterfaceDown),
            (PacketField("message", default=ScmpInternalConnectivityDown(), pkt_cls=ScmpInternalConnectivityDown),
                lambda pkt: pkt.type == SCMP.TypeInternalConnectivityDown),
            (PacketField("message", default=ScmpEchoRequest(), pkt_cls=ScmpEchoRequest),
                lambda pkt: pkt.type == SCMP.TypeEchoRequest),
            (PacketField("message", default=ScmpEchoReply(), pkt_cls=ScmpEchoReply),
                lambda pkt: pkt.type == SCMP.TypeEchoReply),
            (PacketField("message", default=ScmpTracerouteRequest(), pkt_cls=ScmpTracerouteRequest),
                lambda pkt: pkt.type == SCMP.TypeTracerouteRequest),
            (PacketField("message", default=ScmpTracerouteReply(), pkt_cls=ScmpTracerouteReply),
                lambda pkt: pkt.type == SCMP.TypeTracerouteReply)],
            PacketField("message", default=ScmpEchoRequest(), pkt_cls=ScmpEchoRequest)
        )
    ]

    def post_build(self, hdr: bytes, payload: bytes) -> bytes:
        if self.type is None:
            hdr = self.message.type.to_bytes(1, byteorder='big') + hdr[1:]
        return hdr + payload

    def answers(self, other):
        if isinstance(other, SCMP):
            if self.Code == SCMP.TypeEchoRequest and SCMP.TypeEchoReply:
                return (other.EchoRequest.id == self.EchoRequest.id
                    and other.EchoRequest.seq == self.EchoRequest.seq)
            elif other.Code == SCMP.TypeTracerouteRequest and self.Code == SCMP.TypeTracerouteReply:
                return (other.EchoRequest.id == self.EchoRequest.id
                    and other.EchoRequest.seq == self.EchoRequest.seq)
        return False

    def guess_payload_class(self, payload):
        if self.type in [SCMP.TypeDestinationUnreachable,
                         SCMP.TypePacketTooBig,
                         SCMP.TypeParameterProblem,
                         SCMP.TypeExternalInterfaceDown,
                         SCMP.TypeInternalConnectivityDown]:
            return SCIONerror
        else:
            return None


class SCIONerror(SCION):
    name = "SCION in SCMP"


bind_layers(SCION, SCMP, nh=SCION_PROTO_NUMBERS['SCMP'])
bind_layers(HopByHopExt, SCMP, nh=SCION_PROTO_NUMBERS['SCMP'])
bind_layers(EndToEndExt, SCMP, nh=SCION_PROTO_NUMBERS['SCMP'])
