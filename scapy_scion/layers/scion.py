"""
SCION Headers and Extensions
https://docs.scion.org/en/latest/protocols/scion-header.html
https://docs.scion.org/en/latest/protocols/extension-header.html
"""

import array
import base64
import os
import struct
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple, Type

from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from scapy.fields import (
    BitEnumField, BitField, ByteEnumField, ByteField, FieldLenField, FlagsField,
    IP6Field, IPField, MultipleTypeField, PacketField, PacketListField,
    ShortField, XBitField, XShortField, XStrField, XStrLenField
)
from scapy.layers.inet import IP, TCP
from scapy.layers.inet import UDP as _inet_udp
from scapy.layers.inet6 import IPv6
from scapy.packet import (
    Packet, Raw, bind_bottom_up, bind_layers, bind_top_down, split_layers
)
from scapy.utils import checksum

from scapy_scion.fields import AsnField, ExpiryTime, UnixTimestamp

# Assigned SCION protocol numbers
# https://docs.scion.org/en/latest/protocols/assigned-protocol-numbers.html

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
        assert sc.version == 0
        assert sc.nh == 0 or sc.nh in ProtocolNames.keys()
        assert sc.ptype in [0, 1, 2, 3, 4]
        assert sc.dt < 2 and sc.st < 2
        assert sc.dl in [0, 3] and sc.sl in [0, 3]
        assert sc.reserved == 0
        assert len(payload) == 4 * sc.hlen + sc.plen
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

    name = "Empty Path"

    fields_desc = []

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


################################
## Standard SCION Path Header ##
################################

def _count_info_fields(pkt) -> int:
    """Returns the number of info fields expected in the packet."""
    return int(pkt.seg0_len > 0) + int(pkt.seg1_len > 0) + int(pkt.seg2_len > 0)


def _count_hop_fields(pkt) -> int:
    """Returns the number of hop fields expected in the packet."""
    return pkt.seg0_len + pkt.seg1_len + pkt.seg2_len


class InfoField(Packet):
    """"Info field in standard SCION paths."""

    name = "Info Field"

    fields_desc = [
        FlagsField("flags", default=0, size=8, names={
            0x01: "C",
            0x02: "P"
        }),
        BitField("reserved", default=0, size=8),
        XShortField("segid", default=0),
        UnixTimestamp("timestamp", default=datetime.now(tz=timezone.utc))
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class HopField(Packet):
    """Hop field in standard SCION paths."""

    name = "Hop Field"

    fields_desc = [
        FlagsField("flags", default=0, size=8, names={
            0x01: "E",
            0x02: "I"
        }),
        ExpiryTime("exp_time", default=0),
        ShortField("cons_ingress", default=0),
        ShortField("cons_egress", default=1),
        XBitField("mac", default=0, size=48)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class SCIONPath(Packet):
    """Standard SCION Path consisting of up to 3 info fields and 63 hop fields."""

    name = "SCION Path"

    fields_desc = [
        # PathMeta header
        BitField("curr_inf", default=0, size=2),
        BitField("curr_hf", default=0, size=6),
        BitField("reserved", default=0, size=6),
        BitField("seg0_len", default=None, size=6),
        BitField("seg1_len", default=None, size=6),
        BitField("seg2_len", default=None, size=6),

        # Info fields
        PacketListField("info_fields", default=[], pkt_cls=InfoField, count_from=_count_info_fields),

        # Hop fields
        PacketListField("hop_fields", default=[], pkt_cls=HopField, count_from=_count_hop_fields)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s

    class VerificationError(Exception):
        def __str__(self):
            return "Hop field verification failed"

    @staticmethod
    def derive_hf_mac_key(key: str|bytes) -> bytes:
        """
        Helper function deriving the base64-encoded data plane key from the
        base64-encoded AS master key as found in the "master0.key" file of a
        typical SCION AS.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=b"Derive OF Key",
            iterations=1000
        )
        return base64.b64encode(kdf.derive(base64.b64decode(key)))

    @staticmethod
    def _calc_mac(inf: InfoField, hf: HopField, beta: int, key: str|bytes) -> bytes:
        ts = int(inf.timestamp.timestamp())
        exp_time = hf.exp_time
        ingress = hf.cons_ingress
        egress = hf.cons_egress
        cmac_input = struct.pack("!HHIBBHHH", 0, beta, ts, 0, exp_time, ingress, egress, 0)
        c = cmac.CMAC(algorithms.AES(base64.b64decode(key)))
        c.update(cmac_input)
        return c.finalize()

    @staticmethod
    def _init_segment(inf: InfoField, hfs: Iterable[HopField], keys: Iterable[str|bytes], seed):
        beta = [seed]
        for hf, key in zip(hfs, keys):
            mac = SCIONPath._calc_mac(inf, hf, int.from_bytes(beta[-1], byteorder='big'), key)
            hf.mac = int.from_bytes(mac[:6], byteorder='big')
            beta.append(bytes(a ^ b for a, b in zip(beta[-1], mac[:2])))
        return beta

    def _verify_hop_field(self, beta: int, key: str|bytes):
        expected = self._calc_mac(self.info_fields[self.curr_inf], self.hop_fields[self.curr_hf],
            beta, key)
        if self.hop_fields[self.curr_hf].mac.to_bytes(6, byteorder='big') != expected[:6]:
            raise SCIONPath.VerificationError()

    def init_path(self, keys: List, seeds: List[bytes] = []) -> None:
        """"Initialize the MAC and SegID fields.

        ### Parameters
        keys: AS keys for the MAC computation in order of the hop fields
            as they appear in the header.
        seeds: Initial random values (2 bytes per segment) for hop field
            chaining.
        """
        seg_offsets = [
            0,
            self.seg0_len,
            self.seg0_len + self.seg1_len,
            self.seg0_len + self.seg1_len + self.seg2_len
        ]
        for i, inf in enumerate(self.info_fields):
            seg_hfs = self.hop_fields[seg_offsets[i]:seg_offsets[i+1]]
            seg_keys = keys[seg_offsets[i]:seg_offsets[i+1]]
            seed = seeds[i] if i < len(seeds) else os.urandom(2)
            if inf.flags.C:
                beta = self._init_segment(inf, seg_hfs, seg_keys, seed)
                inf.segid = int.from_bytes(beta[0], byteorder='big')
            else:
                beta = self._init_segment(inf, reversed(seg_hfs), reversed(seg_keys), seed)
                inf.segid = int.from_bytes(beta[-2], byteorder='big')

    def egress(self, key: str|bytes) -> None:
        """Perform egress processing on the path as a border router would.

        ### Parameters
        key: Base64-encoded hop verification key

        ## Exceptions
        SCIONPath.VerificationError: Hop field verification failed.
        """
        beta = self.info_fields[self.curr_inf].segid
        self._verify_hop_field(beta, key)

        if self.info_fields[self.curr_inf].flags.C:
            sigma_trunc = self.hop_fields[self.curr_hf].mac >> 32
            self.info_fields[self.curr_inf].segid = beta ^ sigma_trunc

        self.curr_hf += 1

    def ingress(self, key: str|bytes) -> None:
        """Perform ingress processing on the path as a border router would.

        ### Parameters
        key: Base64-encoded hop verification key

        ### Exceptions
        SCIONPath.VerificationError: Hop field verification failed.
        """
        if not self.info_fields[self.curr_inf].flags.C:
            sigma_trunc = self.hop_fields[self.curr_hf].mac >> 32
            beta = self.info_fields[self.curr_inf].segid ^ sigma_trunc
        else:
            beta = self.info_fields[self.curr_inf].segid

        self._verify_hop_field(beta, key)

        if not self.info_fields[self.curr_inf].flags.C:
            self.info_fields[self.curr_inf].segid = beta

        # Switch to the next path segment if necessary
        seg_offsets = [
            self.seg0_len,
            self.seg0_len + self.seg1_len,
            self.seg0_len + self.seg1_len + self.seg2_len
        ]
        next_hf = self.curr_hf + 1
        if next_hf < seg_offsets[2] and next_hf == seg_offsets[self.curr_inf]:
            self.curr_hf = next_hf
            self.curr_inf += 1


#########################
## One Hop Path Header ##
#########################

class OneHopPath(Packet):
    """Special case of SCIONPath with no PathMeta header and exactly one info
    and two hop fields."""

    name = "One-Hop Path"

    fields_desc = [
        PacketField("info_file", default=None, pkt_cls=InfoField),
        PacketField("hop_field0", default=None, pkt_cls=HopField),
        PacketField("hop_field1", default=None, pkt_cls=HopField)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


##################
## SCION Header ##
##################

def scion_checksum(addr_hdr: bytes, payload: bytes, next_hdr: int) -> int:
    """Compute checksum over SCION pseudo header and payload.

    ### Parameters
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
        BitField("version", default=0, size=4),
        XBitField("qos", default=0, size=8),
        XBitField("fl", default=1, size=20),
        ByteEnumField("nh", default=None, enum=ProtocolNames),
        ByteField("hlen", default=None),
        ShortField("plen", default=None),
        ByteEnumField("ptype", default=None, enum= {
            0: "Empty",
            1: "SCION",
            2: "OneHopPath",
            3: "EPIC",
            4: "COLIBRI"
        }),
        BitEnumField("dt", default="IP", size=2, enum=address_types),
        BitField("dl", default=0, size=2),
        BitEnumField("st", default="IP", size=2, enum=address_types),
        BitField("sl", default=0, size=2),
        ShortField("reserved", default=0),

        # Address header
        ShortField("dst_isd", default=1),
        AsnField("dst_asn", default="ff00:0:1"),
        ShortField("src_isd", default=1),
        AsnField("src_asn", default="ff00:0:2"),
        MultipleTypeField([
            (IPField("dst_host", default="127.0.0.1"), lambda pkt: pkt.dt == 0 and pkt.dl == 0),
            (IP6Field("dst_host", default="::1"), lambda pkt: pkt.dt == 0 and pkt.dl == 3)],
            XStrLenField("dst_host", default=None, length_from=lambda pkt: 4 * pkt.dl + 4)
        ),
        MultipleTypeField([
            (IPField("src_host", default="127.0.0.1"), lambda pkt: pkt.st == 0 and pkt.sl == 0),
            (IP6Field("src_host", default="::1"), lambda pkt: pkt.st == 0 and pkt.sl == 3)],
            XStrLenField("src_host", default=None, length_from=lambda pkt: 4 * pkt.sl + 4)
        ),

        # Path
        MultipleTypeField([
            (PacketField("path", None, pkt_cls=EmptyPath), lambda pkt: pkt.ptype == 0),
            (PacketField("path", None, pkt_cls=SCIONPath), lambda pkt: pkt.ptype == 1),
            (PacketField("path", None, pkt_cls=OneHopPath), lambda pkt: pkt.ptype == 2)],
            XStrField("path", default=None)
        ),
    ]

    def get_path_len(self):
        """Compute the length of the SCION path headers."""
        common_hdr_len = 12
        addr_hdr_len = 16 + (4 * self.dl + 4) + (4 * self.sl + 4)
        return 4 * self.hlen - common_hdr_len - addr_hdr_len

    def post_build(self, hdr: bytes, payload: bytes):
        if self.hlen is None:
            hdr_len = len(hdr) // 4
            hdr = hdr[:5] + hdr_len.to_bytes(1, byteorder='big') + hdr[6:]

        if self.plen is None:
            payload_len = len(payload)
            hdr = hdr[:6] + payload_len.to_bytes(2, byteorder='big') + hdr[8:]

        if self.ptype is None:
            if isinstance(self.path, EmptyPath):
                path_type = 0
            elif isinstance(self.path, SCIONPath):
                path_type = 1
            elif isinstance(self.path, OneHopPath):
                path_type = 2
            else:
                path_type = 0xff

            hdr = hdr[:8] + path_type.to_bytes(1, byteorder='big') + hdr[9:]

        # Compute L4 checksum
        for proto in ['SCMP', 'TCP', 'UDP']:
            l4 = self.getlayer(proto)
            if l4 is not None and l4.chksum is None:
                addr_hdr = hdr[12:12+16+(4*self.dl+4)+(4*self.sl+4)]
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
        ByteField("opt_type", default=0)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class PadNOption(Packet):
    """N bytes of padding."""

    name = "PadN"

    fields_desc = [
        ByteField("opt_type", default=1),
        FieldLenField("opt_data_len", default=None, fmt="B", length_of="opt_data"),
        XStrLenField("opt_data", default=b"", length_from=lambda pkt: pkt.opt_data_len)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class AuthenticatorOption(Packet):
    """End-to-end packet authentication option.
    Alignment requirement: 4n+1
    """

    name = "Authenticator"

    fields_desc = [
        ByteField("opt_type", default=2),
        FieldLenField("opt_data_len", default=17, fmt="B", length_of="Authenticator",
            adjust=lambda pkt, x: x + 1),
        ByteEnumField("algorithm", default="AES-CMAC", enum={
            0: "AES-CMAC",
            253: "Exp 1",
            254: "Exp 2",
        }),
        XStrLenField("authenticator", default=16*b"\x00",
            length_from=lambda pkt: pkt.opt_data_len - 1)
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
        ByteEnumField("nh", default=None, enum=ProtocolNames),
        FieldLenField("ext_len", default=None, fmt="B", length_of="options",
            adjust=lambda pkt, x: (x - 2) // 4),
        PacketListField("options", default=[], length_from=lambda pkt: 4 * pkt.ext_len + 2,
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
        ByteEnumField("nh", default=None, enum=ProtocolNames),
        FieldLenField("ext_len", default=None, fmt="B", length_of="options",
            adjust=lambda pkt, x: (x - 2) // 4),
        PacketListField("options", default=[], length_from=lambda pkt: 4 * pkt.ext_len + 2,
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
bind_layers(SCION, TCP, nh=ProtocolNumbers['TCP'])
bind_layers(SCION, UDP, nh=ProtocolNumbers['UDP'])
bind_layers(SCION, HopByHopExt, nh=ProtocolNumbers['HopByHopExt'])
bind_layers(SCION, EndToEndExt, nh=ProtocolNumbers['EndToEndExt'])

bind_layers(HopByHopExt, TCP, nh=ProtocolNumbers['TCP'])
bind_layers(HopByHopExt, UDP, nh=ProtocolNumbers['UDP'])
bind_layers(HopByHopExt, EndToEndExt, nh=ProtocolNumbers['EndToEndExt'])

bind_layers(EndToEndExt, TCP, nh=ProtocolNumbers['TCP'])
bind_layers(EndToEndExt, UDP, nh=ProtocolNumbers['UDP'])
