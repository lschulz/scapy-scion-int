"""
SCION Headers and Extensions
https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html
https://scion.docs.anapaya.net/en/latest/protocols/extension-header.html
"""

import array
import base64
import os
import struct
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple, Type

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from scapy.fields import (BitEnumField, BitField, BitScalingField,
                          ByteEnumField, ByteField, FieldLenField, FlagsField,
                          IP6Field, IPField, MultipleTypeField, PacketField,
                          PacketListField, ScalingField, ShortField, XBitField,
                          XShortField, XStrField, XStrLenField)
from scapy.layers.inet import IP, TCP
from scapy.layers.inet import UDP as _inet_udp
from scapy.layers.inet6 import IPv6
from scapy.packet import (Packet, Raw, bind_bottom_up, bind_layers,
                          bind_top_down, split_layers)
from scapy.utils import checksum

from scapy_scion.fields import AsnField, ExpiryTime, UnixTimestamp

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

##################
## UDP Underlay ##
##################

def _looks_like_scion(payload: bytes) -> bool:
    """Heuristically detect if a payload looks like SCION, c.f.,
    https://github.com/scionproto/scion/blob/master/tools/wireshark/scion.lua
    """
    if len(payload) < 36:
        return False
    try:
        sc = SCION(payload)
        assert sc.Version == 0
        assert sc.NextHdr in ProtocolNames.keys()
        assert sc.PathType in [0, 1, 2, 3, 4]
        assert sc.DT < 2 and sc.ST < 2
        assert sc.DL in [4, 16] and sc.SL in [4, 16]
        assert sc.RSV == 0
        assert len(payload) == sc.HdrLen + sc.PayloadLen
    except AssertionError:
        return False
    return True


class UDP(_inet_udp):
    """UDP with SCION payload detection"""

    def guess_payload_class(self, payload):
        """Heuristic for detecting SCION in UDP"""
        if _looks_like_scion(payload):
            return SCION
        return super().guess_payload_class(payload)


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
            0x01: "C",
            0x02: "P"
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
            0x01: "E",
            0x02: "I"
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

    class VerificationError(Exception):
        def __str__(self):
            return "Hop field verification failed"

    @staticmethod
    def _calc_mac(inf: InfoField, hf: HopField, beta: int, key: str) -> bytes:
        ts = int(inf.Timestamp.timestamp())
        exp_time = hf.ExpTime
        ingress = hf.ConsIngress
        egress = hf.ConsEgress
        cmac_input = struct.pack("!HHIBBHHH", 0, beta, ts, 0, exp_time, ingress, egress, 0)
        c = cmac.CMAC(algorithms.AES(base64.b64decode(key)))
        c.update(cmac_input)
        return c.finalize()

    @staticmethod
    def _init_segment(inf: InfoField, hfs: Iterable[HopField], keys: Iterable[str], seed):
        beta = [seed]
        for hf, key in zip(hfs, keys):
            mac = SCIONPath._calc_mac(inf, hf, int.from_bytes(beta[-1], byteorder='big'), key)
            hf.MAC = int.from_bytes(mac[:6], byteorder='big')
            beta.append(bytes(a ^ b for a, b in zip(beta[-1], mac[:2])))
        return beta

    def _verify_hop_field(self, beta: int, key: str):
        expected = self._calc_mac(self.InfoFields[self.CurrINF], self.HopFields[self.CurrHF],
            beta, key)
        if self.HopFields[self.CurrHF].MAC.to_bytes(6, byteorder='big') != expected[:6]:
            raise SCIONPath.VerificationError()

    def init_path(self, keys: List, seeds: List[bytes] = []) -> None:
        """"Initialize the MAC and SegID fields.
        :param keys: AS keys for the MAC computation in order of the hop fields as they appear in
                     the header.
        :param seeds: Initial random values (2 bytes per segment) for hop field chaining.
        """
        seg_offsets = [
            0,
            self.Seg0Len,
            self.Seg0Len + self.Seg1Len,
            self.Seg0Len + self.Seg1Len + self.Seg2Len
        ]
        for i, inf in enumerate(self.InfoFields):
            seg_hfs = self.HopFields[seg_offsets[i]:seg_offsets[i+1]]
            seg_keys = keys[seg_offsets[i]:seg_offsets[i+1]]
            seed = seeds[i] if i < len(seeds) else os.urandom(2)
            if inf.Flags.C:
                beta = self._init_segment(inf, seg_hfs, seg_keys, seed)
                inf.SegID = int.from_bytes(beta[0], byteorder='big')
            else:
                beta = self._init_segment(inf, reversed(seg_hfs), reversed(seg_keys), seed)
                inf.SegID = int.from_bytes(beta[-2], byteorder='big')

    def egress(self, key: str) -> None:
        """Perform egress processing on the path as a border router would.
        :param key: Base64-encoded hop verification key
        :raises: SCIONPath.VerificationError: Hop field verification failed.
        """
        beta = self.InfoFields[self.CurrINF].SegID
        self._verify_hop_field(beta, key)

        if self.InfoFields[self.CurrINF].Flags.C:
            sigma_trunc = self.HopFields[self.CurrHF].MAC >> 32
            self.InfoFields[self.CurrINF].SegID = beta ^ sigma_trunc

        self.CurrHF += 1

    def ingress(self, key: str) -> None:
        """Perform ingress processing on the path as a border router would.
        :param key: Base64-encoded hop verification key
        :raises: SCIONPath.VerificationError: Hop field verification failed.
        """
        if not self.InfoFields[self.CurrINF].Flags.C:
            sigma_trunc = self.HopFields[self.CurrHF].MAC >> 32
            beta = self.InfoFields[self.CurrINF].SegID ^ sigma_trunc
        else:
            beta = self.InfoFields[self.CurrINF].SegID

        self._verify_hop_field(beta, key)

        if not self.InfoFields[self.CurrINF].Flags.C:
            self.InfoFields[self.CurrINF].SegID = beta

        # Switch to the next path segment if necessary
        seg_offsets = [
            self.Seg0Len,
            self.Seg0Len + self.Seg1Len,
            self.Seg0Len + self.Seg1Len + self.Seg2Len
        ]
        next_hf = self.CurrHF + 1
        if next_hf < seg_offsets[2] and next_hf == seg_offsets[self.CurrINF]:
            self.CurrHF = next_hf
            self.CurrINF += 1


#########################
## One Hop Path Header ##
#########################

class OneHopPath(Packet):
    """Special case of SCIONPath with no PathMeta header and exactly one info and two hop fields."""

    name = "OneHopPath"

    fields_desc = [
        PacketField("InfoField", default=None, pkt_cls=InfoField),
        PacketField("HopField0", default=None, pkt_cls=HopField),
        PacketField("HopField1", default=None, pkt_cls=HopField)
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

    chksum = checksum(data.tobytes())
    return 0xffff if chksum == 0 else chksum


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
        for proto in ['SCMP', 'TCP', 'UDP']:
            l4 = self.getlayer(proto)
            if l4 is not None:
                addr_hdr = hdr[12:12+16+self.DL+self.SL]
                l4.chksum = scion_checksum(addr_hdr, bytes(l4), ProtocolNumbers[proto])
                payload = bytes(self.payload) # Update the payload
                break

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
            adjust=lambda pkt, x: (x - 2) // 4),
        PacketListField("Options", default=[], length_from=lambda pkt: 4 * pkt.ExtLen + 2,
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
            adjust=lambda pkt, x: (x - 2) // 4),
        PacketListField("Options", default=[], length_from=lambda pkt: 4 * pkt.ExtLen + 2,
            pkt_cls=_detect_e2e_option_type)
    ]

# Replace default UDP layer with our overridden UDP layer
split_layers(IP, _inet_udp, frag=0, proto=17)
bind_layers(IP, UDP, frag=0, proto=17)
split_layers(IPv6, _inet_udp, nh=17)
bind_layers(IPv6, UDP, nh=17)

# Bind default port ranges to IP/UDP underlay
# https://github.com/scionproto/scion/wiki/Default-port-ranges
# Control service
bind_bottom_up(UDP, SCION, dport=30252)
bind_bottom_up(UDP, SCION, sport=30252)
# Border routers
for port in range(30042, 30052):
    bind_bottom_up(UDP, SCION, dport=port)
    bind_bottom_up(UDP, SCION, sport=port)
# SIG
bind_bottom_up(UDP, SCION, dport=30256)
bind_bottom_up(UDP, SCION, sport=30256)
bind_bottom_up(UDP, SCION, dport=30056)
bind_bottom_up(UDP, SCION, sport=30056)
# Dispatcher
bind_bottom_up(UDP, SCION, dport=30041)
bind_bottom_up(UDP, SCION, sport=30041)

# Default ports for constructing SCION packets
bind_top_down(UDP, SCION, {'dport': 30042, 'sport': 30042})

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
