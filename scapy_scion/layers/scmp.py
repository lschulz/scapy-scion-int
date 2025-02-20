"""
SCION Control Message Protocol
https://docs.scion.org/en/latest/protocols/scmp.html
"""

from typing import Optional, Tuple

from scapy.fields import (ByteEnumField, ByteField, IntField, LongField,
                          MultipleTypeField, PacketField, ShortField,
                          XShortField, XStrField)
from scapy.packet import Packet, bind_layers

from ..fields import AsnField
from .scion import SCION, TCP, UDP, EndToEndExt, HopByHopExt, ProtocolNumbers

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


class _ScmpMessage(Packet):
    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class Unreachable(_ScmpMessage):
    """SCMP Destination Unreachable"""

    name = "Destination Unreachable"

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
        IntField("Unused", default=0)
    ]


class PacketTooBig(_ScmpMessage):
    """SCMP Packet Too Big"""

    name = "Packet Too Big"

    fields_desc = [
        ShortField("reserved", default=0),
        ShortField("MTU", default=1280)
    ]


class ParameterProblem(_ScmpMessage):
    """SCMP Parameter Problem"""

    name = "Parameter Problem"

    codes = {
        0: "erroneous header field",
        1: "unknown header field",
        16: "invalid common header",
        17: "unknown SCION version",
        18: "FlowID required",
        19: "invalid packet size",
        20: "unknown oath type",
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
        ShortField("Pointer", default=0)
    ]


class ExternalInterfaceDown(_ScmpMessage):
    """SCMP External Interface Down"""

    name = "External Interface Down"

    fields_desc = [
        ShortField("ISD", default=0),
        AsnField("AS", default="0"),
        LongField("Interface", default=0)
    ]


class InternalConnectivityDown(_ScmpMessage):
    """SCMP Internal Connectivity Down"""

    name = "Internal Connectivity Down"

    fields_desc = [
        ShortField("ISD", default=0),
        AsnField("AS", default="0"),
        LongField("IngressInterface", default=0),
        LongField("EgressInterface", default=0)
    ]


class EchoRequest(_ScmpMessage):
    """SCMP Echo Request"""

    name = "Echo Request"

    fields_desc = [
        ShortField("Identifier", default=0),
        ShortField("Sequence", default=0)
    ]


class EchoReply(_ScmpMessage):
    """SCMP Echo Reply"""

    name = "Echo Reply"

    fields_desc = [
        ShortField("Identifier", default=0),
        ShortField("Sequence", default=0)
    ]


class TracerouteRequest(_ScmpMessage):
    """SCMP Traceroute Request"""

    name = "Traceroute Request"

    fields_desc = [
        ShortField("Identifier", default=0),
        ShortField("Sequence", default=0),
        ShortField("ISD", default=0),
        AsnField("AS", default="0"),
        LongField("IngressInterface", default=0),
    ]


class TracerouteReply(_ScmpMessage):
    """SCMP Traceroute Reply"""

    name = "Traceroute Reply"

    fields_desc = [
        ShortField("Identifier", default=0),
        ShortField("Sequence", default=0),
        ShortField("ISD", default=0),
        AsnField("AS", default="0"),
        LongField("IngressInterface", default=0),
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
        ByteEnumField("Type", default="Echo Request", enum=SCMPTypes),
        ByteField("Code", default=0),
        XShortField("chksum", default=None), # Checksum is computed in SCION layer
        MultipleTypeField([
            (PacketField("Message", default=Unreachable(), pkt_cls=Unreachable),
                lambda pkt: pkt.Type == SCMP.TypeDestinationUnreachable),
            (PacketField("Message", default=PacketTooBig(), pkt_cls=PacketTooBig),
                lambda pkt: pkt.Type == SCMP.TypePacketTooBig),
            (PacketField("Message", default=ParameterProblem(), pkt_cls=ParameterProblem),
                lambda pkt: pkt.Type == SCMP.TypeParameterProblem),
            (PacketField("Message", default=ExternalInterfaceDown(), pkt_cls=ExternalInterfaceDown),
                lambda pkt: pkt.Type == SCMP.TypeExternalInterfaceDown),
            (PacketField("Message", default=InternalConnectivityDown(), pkt_cls=InternalConnectivityDown),
                lambda pkt: pkt.Type == SCMP.TypeInternalConnectivityDown),
            (PacketField("Message", default=EchoRequest(), pkt_cls=EchoRequest),
                lambda pkt: pkt.Type == SCMP.TypeEchoRequest),
            (PacketField("Message", default=EchoReply(), pkt_cls=EchoReply),
                lambda pkt: pkt.Type == SCMP.TypeEchoReply),
            (PacketField("Message", default=TracerouteRequest(), pkt_cls=TracerouteRequest),
                lambda pkt: pkt.Type == SCMP.TypeTracerouteRequest),
            (PacketField("Message", default=TracerouteReply(), pkt_cls=TracerouteReply),
                lambda pkt: pkt.Type == SCMP.TracerouteReply)],
            XStrField("Message", default=None)
        )
    ]

    def answers(self, other):
        if isinstance(other, SCMP):
            if self.Code == SCMP.TypeEchoRequest and SCMP.TypeEchoReply:
                return (other.EchoRequest.Identifier == self.EchoRequest.identifier
                    and other.EchoRequest.Sequence == self.EchoRequest.Sequence)
            elif other.Code == SCMP.TypeTracerouteRequest and self.Code == SCMP.TypeTracerouteReply:
                return (other.EchoRequest.Identifier == self.EchoRequest.identifier
                    and other.EchoRequest.Sequence == self.EchoRequest.Sequence)
        return False

    def guess_payload_class(self, payload):
        if self.Type in [SCMP.TypeDestinationUnreachable,
                         SCMP.TypePacketTooBig,
                         SCMP.TypeParameterProblem,
                         SCMP.TypeExternalInterfaceDown,
                         SCMP.TypeInternalConnectivityDown]:
            return SCIONerror
        else:
            return None


class SCIONerror(SCION):
    name = "SCION in SCMP"


bind_layers(SCION, SCMP, NextHdr=ProtocolNumbers['SCMP'])
bind_layers(HopByHopExt, SCMP, NextHdr=ProtocolNumbers['SCMP'])
bind_layers(EndToEndExt, SCMP, NextHdr=ProtocolNumbers['SCMP'])
