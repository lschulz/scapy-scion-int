"""
SCION Headers and Extensions
https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html
https://scion.docs.anapaya.net/en/latest/protocols/extension-header.html
"""

import array
from datetime import datetime, timezone
from typing import Optional, Tuple, Type

from fields import AsnField, ExpiryTime, UnixTimestamp
from scapy.fields import (BitEnumField, BitField, BitScalingField,
                          ByteEnumField, ByteField, FieldLenField, FlagsField,
                          IP6Field, IPField, MultipleTypeField, PacketField,
                          PacketListField, ScalingField, ShortField, XBitField,
                          XShortField, XStrField, XStrLenField)
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, Raw, bind_layers
from scapy.utils import checksum


# Assigned SCION protocol numbers
# https://scion.docs.anapaya.net/en/latest/protocols/assigned-protocol-numbers.html

ProtocolNames = {
    6: "TCP",
    17: "UDP",
    200: "HopByHopExt",
    201: "EndToEndExt",
    202: "SCMP",
    203: "BFD",
    253: "Experiment1",
    254: "Experiment2",
}

ProtocolNumbers = {
    "TCP": 6,
    "UDP": 17,
    "HopByHopExt": 200,
    "EndToEndExt": 201,
    "SCMP": 202,
    "BFD": 203,
    "Experiment1": 253,
    "Experiment2": 254,
}


#######################
## Empty Path Header ##
#######################

class EmptyPath(Packet):
    """Empty Path"""

    name = "Empty"

    fields_desc = []

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


################################
## Standard SCION Path Header ##
################################

def countInfoFields(pkt) -> int:
    """Returns the number of info fields expected in the packet."""
    return int(pkt.Seg0Len > 0) + int(pkt.Seg1Len > 0) + int(pkt.Seg2Len > 0)


def countHopFields(pkt) -> int:
    """Returns the number of hop fields expected in the packet."""
    return pkt.Seg0Len + pkt.Seg1Len + pkt.Seg2Len


class InfoField(Packet):
    """"Info field in standard SCION paths."""

    name = "Info Field"

    fields_desc = [
        FlagsField("Flags", default=0, size=8, names={
            0: "C", 1: "P"
        }),
        BitField("RSV", default=0, size=8),
        XShortField("SegID", default=0),
        UnixTimestamp("Timestamp", default=datetime.now(tz=timezone.utc))
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class HopField(Packet):
    """Hop field in standard SCION paths."""

    name = "Hop field"

    fields_desc = [
        FlagsField("Flags", default=0, size=8, names={
            0: "E", 1: "I"
        }),
        ExpiryTime("ExpTime", default=0),
        ShortField("ConsIngress", default=0),
        ShortField("ConsEgress", default=1),
        XBitField("MAC", default=0, size=48)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class SCIONPath(Packet):
    """Standard SCION Path consisting of up to 3 info fields and 64 hop fields."""

    name = "SCION Path"

    fields_desc = [
        # PathMeta header
        BitField("CurrINF", default=0, size=2),
        BitField("CurrHF", default=0, size=6),
        BitField("RSV", default=0, size=6),
        BitField("Seg0Len", default=None, size=6),
        BitField("Seg1Len", default=None, size=6),
        BitField("Seg2Len", default=None, size=6),

        # Info fields
        PacketListField("InfoFields", default=[], pkt_cls=InfoField, count_from=countInfoFields),

        # Hop fields
        PacketListField("HopFields", default=[], pkt_cls=HopField, count_from=countHopFields)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


#########################
## One Hop Path Header ##
#########################

class OneHopPath(Packet):
    """Special case of SCIONPath with no PathMeta header and exactly one info and two hop fields."""

    name = "OneHopPath"

    fields_desc = [
        PacketField("InfoField", default=None, pkt_cls=InfoField),
        PacketField("HopField 0", default=None, pkt_cls=HopField),
        PacketField("HopField 1", default=None, pkt_cls=HopField)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


##################
## SCION Header ##
##################

def scion_checksum(addr_hdr: bytes, payload: bytes, next_hdr: int) -> int:
    """Compute checksum over SCION pseudo header and payload.

    Parameters:
    addr_hdr: Raw SCION address header.
    payload : Raw upper-layer payload. Must not include any SCION extension headers.
    next_hdr: SCION protocol identifier of the payload protocol.
    """
    data = array.array("B")

    data.extend(addr_hdr)
    data.extend(len(payload).to_bytes(4, byteorder='big'))
    data.extend(b"\x00\x00\x00")
    data.extend(next_hdr.to_bytes(1, byteorder='big'))
    data.extend(payload)

    return checksum(data.tobytes())


class SCION(Packet):
    """SCION common header, address header, and path."""

    name = "SCION"

    address_types = {
        0: "IP",
    }

    fields_desc = [
        # Common header
        BitField("Version", default=0, size=4),
        XBitField("QoS", default=0, size=8),
        XBitField("FlowID", default=1, size=20),
        ByteEnumField("NextHdr", default=None, enum=ProtocolNames),
        ScalingField("HdrLen", default=0, fmt='B', scaling=4, unit="bytes"),
        ShortField("PayloadLen", default=None),
        ByteEnumField("PathType", default=None, enum= {
            0: "Empty",
            1: "SCION",
            2: "OneHopPath",
            3: "EPIC",
            4: "COLIBRI"
        }),
        BitEnumField("DT", default="IP", size=2, enum=address_types),
        BitScalingField("DL", default=4, size=2, scaling=4, offset=4, unit="bytes"),
        BitEnumField("ST", default="IP", size=2, enum=address_types),
        BitScalingField("SL", default=4, size=2, scaling=4, offset=4, unit="bytes"),
        ShortField("RSV", default=0),

        # Address header
        ShortField("DstISD", default=1),
        AsnField("DstAS", default="ff00:0:1"),
        ShortField("SrcISD", default=1),
        AsnField("SrcAS", default="ff00:0:2"),
        MultipleTypeField([
            (IPField("DstHostAddr", default="127.0.0.1"), lambda pkt: pkt.DT == 0 and pkt.DL == 4),
            (IP6Field("DstHostAddr", default="::1"), lambda pkt: pkt.DT == 0 and pkt.DL == 16)],
            XStrLenField("DstHostAddr", default=None, length_from=lambda pkt: pkt.DL)
        ),
        MultipleTypeField([
            (IPField("SrcHostAddr", default="127.0.0.1"), lambda pkt: pkt.ST == 0 and pkt.SL == 4),
            (IP6Field("SrcHostAddr", default="::1"), lambda pkt: pkt.ST == 0 and pkt.SL == 16)],
            XStrLenField("SrcHostAddr", default=None, length_from=lambda pkt: pkt.SL)
        ),

        # Path
        MultipleTypeField([
            (PacketField("Path", None, pkt_cls=EmptyPath), lambda pkt: pkt.PathType == 0),
            (PacketField("Path", None, pkt_cls=SCIONPath), lambda pkt: pkt.PathType == 1),
            (PacketField("Path", None, pkt_cls=OneHopPath), lambda pkt: pkt.PathType == 2)],
            XStrField("Path", default=None)
        ),
    ]

    def get_path_len(self):
        """Compute the length of the SCION Path headers."""
        common_hdr_len = 12
        addr_hdr_len = 16 + self.DL + self.SL
        return self.HdrLen - common_hdr_len - addr_hdr_len

    def post_build(self, hdr: bytes, payload: bytes):
        if self.HdrLen == 0:
            hdr_len = len(hdr) // 4
            hdr = hdr[:5] + hdr_len.to_bytes(1, byteorder='big') + hdr[6:]

        if self.PayloadLen is None:
            payload_len = len(payload)
            hdr = hdr[:6] + payload_len.to_bytes(2, byteorder='big') + hdr[8:]

        if self.PathType is None:
            if isinstance(self.Path, EmptyPath):
                path_type = 0
            elif isinstance(self.Path, SCIONPath):
                path_type = 1
            elif isinstance(self.Path, OneHopPath):
                path_type = 2
            else:
                path_type = 0xff

            hdr = hdr[:8] + path_type.to_bytes(1, byteorder='big') + hdr[9:]

        # Compute L4 checksum

        scmp = self.getlayer('SCMP')
        if scmp is not None:
            addr_hdr = hdr[12:12+16+self.DL+self.SL]
            scmp.Checksum = scion_checksum(addr_hdr, bytes(scmp), ProtocolNumbers['SCMP'])
            payload = bytes(self.payload) # Update the payload

        udp = self.getlayer('UDP')
        if udp is not None:
            addr_hdr = hdr[12:12+16+self.DL+self.SL]
            udp.chksum = scion_checksum(addr_hdr, bytes(udp), ProtocolNumbers['UDP'])
            if udp.chksum == 0:
                udp.chksum = 0xffff
            payload = bytes(self.payload) # Update the payload

        return hdr + payload


##########################
## SCION Option Headers ##
##########################

class Pad1Option(Packet):
    """A single byte of padding."""

    name = "Pad1"

    fields_desc = [
        ByteField("OptType", default=0)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class PadNOption(Packet):
    """N bytes of padding."""

    name = "PadN"

    fields_desc = [
        ByteField("OptType", default=1),
        FieldLenField("OptDataLen", default=None, fmt="B", length_of="OptData"),
        XStrLenField("OptData", default=b"", length_from=lambda pkt: pkt.OptDataLen)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class AuthenticatorOption(Packet):
    """End-to-end packet authentication option.
    Alignment requirement: 4n+1
    """

    name = "Authenticator"

    fields_desc = [
        ByteField("OptType", default=2),
        FieldLenField("OptDataLen", default=17, fmt="B", length_of="Authenticator",
            adjust=lambda pkt, x: x + 1),
        ByteEnumField("Algorithm", default="AES-CMAC", enum={
            0: "AES-CMAC",
            253: "Exp 1",
            254: "Exp 2",
        }),
        XStrLenField("Authenticator", default=16*b"\x00",
            length_from=lambda pkt: pkt.OptDataLen - 1)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


_hdh_option_types = {
    0: Pad1Option,
    1: PadNOption
}

def add_hbh_option_type(type_id: int, cls: Type):
    """Add or replace a hop-by-hop option header."""
    _hdh_option_types[type_id] = cls

def _detect_hbh_option_type(pkt: bytes, **kwargs):
    cls = _hdh_option_types.get(pkt[0], Raw)
    return cls(pkt, **kwargs)

class HopByHopExt(Packet):
    """SCION Hop-by-Hop Options Header"""

    name = "SCION Hop-by-Hop Options"

    fields_desc = [
        ByteEnumField("NextHdr", default=None, enum=ProtocolNames),
        FieldLenField("ExtLen", default=None, fmt="B", length_of="Options",
            adjust=lambda pkt, x: (x + 2) // 4),
        PacketListField("Options", default=[], length_from=lambda pkt: 4 * pkt.ExtLen - 2,
            pkt_cls=_detect_hbh_option_type)
    ]


_e2e_option_types = {
    0: Pad1Option,
    1: PadNOption,
    2: AuthenticatorOption
}

def add_e2e_option_type(type_id: int, cls: Type):
    """Add or replace an end-to-end option header."""
    _e2e_option_types[type_id] = cls

def _detect_e2e_option_type(pkt: bytes, **kwargs):
    cls = _e2e_option_types.get(pkt[0], Raw)
    return cls(pkt, **kwargs)

class EndToEndExt(Packet):
    """SCION End-to-End Options Header"""

    name = "SCION End-to-End Options"

    fields_desc = [
        ByteEnumField("NextHdr", default=None, enum=ProtocolNames),
        FieldLenField("ExtLen", default=None, fmt="B", length_of="Options",
            adjust=lambda pkt, x: (x + 2) // 4),
        PacketListField("Options", default=[], length_from=lambda pkt: 4 * pkt.ExtLen - 2,
            pkt_cls=_detect_e2e_option_type)
    ]


# Bind to IP/UDP underlay
bind_layers(UDP, SCION, {'sport': 50000, 'dport': 50000})

# Bind upper-layer protocols
bind_layers(SCION, TCP, NextHdr=ProtocolNumbers['TCP'])
bind_layers(SCION, UDP, NextHdr=ProtocolNumbers['UDP'])
bind_layers(SCION, HopByHopExt, NextHdr=ProtocolNumbers['HopByHopExt'])
bind_layers(SCION, EndToEndExt, NextHdr=ProtocolNumbers['EndToEndExt'])

bind_layers(HopByHopExt, TCP, NextHdr=ProtocolNumbers['TCP'])
bind_layers(HopByHopExt, UDP, NextHdr=ProtocolNumbers['UDP'])
bind_layers(HopByHopExt, EndToEndExt, NextHdr=ProtocolNumbers['EndToEndExt'])

bind_layers(EndToEndExt, TCP, NextHdr=ProtocolNumbers['TCP'])
bind_layers(EndToEndExt, UDP, NextHdr=ProtocolNumbers['UDP'])
