"""
Inter-Domain In-band Network Telemetry for SCION
https://github.com/netsys-lab/id-int-spec
"""

import math
import time
from typing import Callable, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.fields import (
    BitEnumField, BitField, BitScalingField, ByteEnumField, ByteField, ConditionalField, Field,
    FlagsField, IntField, IP6Field, IPField, MultipleTypeField, PacketListField, ShortField,
    StrLenField, XStrFixedLenField, XStrLenField
)
from scapy.packet import Packet

from scapy_scion.fields import AsnField, IntegerField
from scapy_scion.layers import scion


IdIntMainOptType = 2
IdIntEntryOptType = 3

_inst_bitmap = {
    2**(3 - 0): "node_id",
    2**(3 - 1): "node_cnt",
    2**(3 - 2): "igif",
    2**(3 - 3): "egif"
}

_instructions = {
    0x00: "nop",
    0x01: "isd",
    0x02: "br_link_type",
    0x03: "device_type_role",
    0x04: "cpu_mem_usage",
    0x05: "cpu_temp",
    0x06: "asic_temp",
    0x07: "fan_speed",
    0x08: "total_power",
    0x09: "energy_mix",
    0x41: "device_vendor",
    0x42: "device_model",
    0x43: "software_version",
    0x44: "node_ipv4_addr",
    0x45: "ingress_if_speed",
    0x46: "egress_if_speed",
    0x47: "gps_lat",
    0x48: "gps_long",
    0x49: "uptime",
    0x4A: "fwd_energy",
    0x4B: "co2_emission",
    0x4C: "ingress_link_rx",
    0x4D: "egress_link_tx",
    0x4E: "queue_id",
    0x4F: "inst_queue_len",
    0x50: "avg_queue_len",
    0x51: "buffer_id",
    0x52: "inst_buffer_occ",
    0x53: "avg_buffer_occ",
    0x81: "asn",
    0x82: "ingress_tstamp",
    0x83: "egress_tstamp",
    0x84: "ig_scif_pkt_cnt",
    0x85: "eg_scif_pkt_cnt",
    0x86: "ig_scif_pkt_drop",
    0x87: "eg_scif_pkt_drop",
    0x88: "ig_scif_bytes",
    0x89: "eg_scif_bytes",
    0x8A: "ig_pkt_cnt",
    0x8B: "eg_pkt_cnt",
    0x8C: "ig_pkt_drop",
    0x8D: "eg_pkt_drop",
    0x8E: "ig_bytes",
    0x8F: "eg_bytes",
    0xC1: "node_ipv6_addr_h",
    0xC2: "node_ipv6_addr_l",
}

_aggregation_functions = {
    0: "first",
    1: "last",
    2: "minimum",
    3: "maximum",
    4: "sum"
}


class VerificationError(Exception):
    def __str__(self):
        return "IDINT metadata verification failed"


def _cbcmac(input: bytes, key: bytes) -> bytes:
    """Calculate the AES CBC-MAC of the input."""
    algo = algorithms.AES(key)
    ecb = Cipher(algo, modes.ECB())
    enc = ecb.encryptor()

    bs = algo.block_size // 8
    blocks = int(math.ceil(len(input) / bs))

    mac = bytearray(16)
    for i in range(blocks):
        for i, (a, b) in enumerate(zip(mac, input[i*bs:])):
            mac[i] = a ^ b
        mac = bytearray(enc.update(mac))

    return bytes(mac)


class MetadataLenField(BitField):
    """Length field for metadata slots.

    The internal representation is an integer number of bytes, the machine
    representation is encoded as follows:
    Size     Encoding
    0 bytes  000b
    2 bytes  100b
    4 bytes  101b
    6 bytes  110b
    8 bytes  111b
    """

    __slots__ = ["length_of"]

    def __init__(self, name, length_of):
        super(BitField, self).__init__(name, None, 3)
        self.length_of = length_of

    def i2m(self, pkt, x: Optional[int]) -> int:
        if x is None and pkt is not None:
            fld, fval = pkt.getfield_and_val(self.length_of)
            x = fld.i2len(pkt, fval)
        elif x is None:
            x = 0
        if x not in [0, 2, 4, 6, 8]:
            raise Exception("Invalid metadata field length")
        return 4 + ((x - 2) >> 1) if x > 0 else 0

    def m2i(self, pkt, x: int) -> int:
        return ((x - 4) << 1) + 2 if x > 0 else 0


class MetadataPadField(Field[bytes, bytes]):
    """Variable size padding for metadata stack alignment"""

    __slots__ = ["_align", "_length_from", "_padwith"]

    def __init__(self, name, align: int, length_from: Callable[[Packet], int], padwith: bytes=None):
        Field.__init__(self, name, default=None)
        self._align = align
        self._length_from = length_from
        if padwith is None:
            self._padwith = (align - 1) * b"\x00"
        else:
            self._padwith = padwith + (align - 1 - len(padwith)) * b"\00"

    def padlen(self, pkt: Packet) -> int:
        length = self._length_from(pkt)
        return -length % self._align

    def i2m(self, pkt, x: Optional[bytes]) -> bytes:
        if x is None and pkt is not None:
            padding = self.padlen(pkt)
        elif x is None:
            padding = 0
        else:
            padding = len(x)
        return self._padwith[:padding]

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, bytes]:
        padding = s[:self.padlen(pkt)]
        return (s[len(padding):], padding)

    def addfield(self, pkt: Packet, s: bytes, val: bytes) -> bytes:
        return s + self.i2m(pkt, val)


class IdIntEntry(Packet):
    """Entry on the ID-INT metadata stack.

    ID-INT entries are stored hop-by-hop SCION options. Alignment requirement:
    4. IdIntEntry options are always a multiple of 4 bytes long.
    """

    name = "IdIntEntry"

    fields_desc = [
        ByteField("type", default=IdIntEntryOptType),
        ByteField("data_len", default=None),
        FlagsField("flags", default=0, size=5, names={
            2**(4 - 0): "source",
            2**(4 - 1): "ingress",
            2**(4 - 2): "egress",
            2**(4 - 3): "aggregate",
            2**(4 - 4): "encrypted"
        }),
        BitField("reserved1", default=0, size=3),
        BitField("hop", default=0, size=6),
        BitField("reserved2", default=0, size=2),
        FlagsField("mask", default=0, size=4, names=_inst_bitmap),
        MetadataLenField("ml1", length_of="md1"),
        MetadataLenField("ml2", length_of="md2"),
        MetadataLenField("ml3", length_of="md3"),
        MetadataLenField("ml4", length_of="md4"),
        ConditionalField(XStrFixedLenField("nonce", default=12*b"\x00", length=12),
            lambda pkt: pkt.flags.encrypted),
        ConditionalField(IntField("node_id", default=0), lambda pkt: pkt.mask.node_id),
        ConditionalField(ShortField("node_cnt", default=0), lambda pkt: pkt.mask.node_cnt),
        ConditionalField(ShortField("igif", default=0), lambda pkt: pkt.mask.igif),
        ConditionalField(ShortField("egif", default=0), lambda pkt: pkt.mask.egif),
        StrLenField("md1", default=b"", length_from=lambda pkt: pkt.ml1),
        StrLenField("md2", default=b"", length_from=lambda pkt: pkt.ml2),
        StrLenField("md3", default=b"", length_from=lambda pkt: pkt.ml3),
        StrLenField("md4", default=b"", length_from=lambda pkt: pkt.ml4),
        MetadataPadField("padding", 4, length_from=lambda pkt: pkt._get_md_len() + 2),
        XStrFixedLenField("mac", default=b"\x00\x00\x00\x00", length=4)
    ]

    def _get_md_len(self) -> int:
        """Returns the length of the metadata fields in bytes."""
        length = 0
        length += 4 if self.mask.node_id else 0
        length += 2 if self.mask.node_cnt else 0
        length += 2 if self.mask.igif else 0
        length += 2 if self.mask.egif else 0
        length += len(self.md1) + len(self.md2) + len(self.md3) + len(self.md4)
        return length

    def length(self) -> int:
        """Returns the entry's total length in bytes."""
        hdr_len = 10 + self._get_md_len()
        if self.flags.encrypted:
            hdr_len += 12
        return (hdr_len + 3) & ~0x03

    def post_build(self, hdr: bytes, payload: bytes):
        if self.data_len is None:
            hdr = hdr[:1] + self.length().to_bytes(1, byteorder='big') + hdr[2:]
        return hdr + payload

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s

    def calc_source_mac(self, hdr: "IdIntOption", key: bytes) -> bytes:
        """Compute the MAC for the source hop.

        ### Parameters
        hdr: IDINT main header. The source MAC includes fields from the main header.
        key: AES-128 key for AES-MAC computation.

        ### Returns
        4-byte MAC
        """
        hdr = hdr.copy()
        hdr.tos = 0
        hdr.delay_hops = 0
        hdr.stack = []
        hdr.remove_payload()
        mac = _cbcmac(bytes(hdr) + bytes(self)[:-4], key)
        return mac[:4]

    def calc_mac(self, prev_mac: bytes, key: bytes) -> bytes:
        """Compute the metadata MAC.

        ### Parameters
        prev_mac: MAC of the previous stack entry.
        key: AES-128 key for AES-MAC computation.

        ### Returns
        4-byte MAC
        """
        mac = _cbcmac(bytes(self)[:-4] + prev_mac, key)
        return mac[:4]


class IdIntOption(Packet):
    """ID-INT SCION hop-by-hop option main header.

    Alignment requirement: 4n+2. IdIntEntry options are always a multiple of 4
    bytes long.

    The main ID-INT option header is immediately followed by one or more
    IdIntEntry options and zero or more PadN options.
    """

    name = "ID-INT"

    fields_desc = [
        ByteField("type", default=IdIntMainOptType),
        ByteField("data_len", default=None),
        BitField("version", default=0, size=3),
        FlagsField("flags", default=0, size=5, names={
            2**(4 - 0): "infrastructure",
            2**(4 - 1): "discard",
            2**(4 - 2): "encrypted",
            2**(4 - 3): "size_exceeded",
        }),
        BitEnumField("aggregation", default=0, size=2, enum={
            0: "off",
            1: "as",
            2: "border",
            3: "internal"
        }),
        BitEnumField("verifier", default=1, size=2, enum={
            0: "third_party",
            1: "destination",
            2: "source"
        }),
        BitEnumField("vt", default="IP", size=2, enum=scion.SCION.address_types),
        BitScalingField("vl", default=4, size=2, scaling=4, offset=4, unit="bytes"),
        ByteField("stack_len", default=None),
        ByteField("tos", default=None),
        BitField("delay_hops", default=0, size=6),
        BitField("reserved", default=0, size=10),
        FlagsField("inst_flags", default=0, size=4, names=_inst_bitmap),
        BitEnumField("af1", default=0, size=3, enum=_aggregation_functions),
        BitEnumField("af2", default=0, size=3, enum=_aggregation_functions),
        BitEnumField("af3", default=0, size=3, enum=_aggregation_functions),
        BitEnumField("af4", default=0, size=3, enum=_aggregation_functions),
        ByteEnumField("inst1", default=0xff, enum=_instructions),
        ByteEnumField("inst2", default=0xff, enum=_instructions),
        ByteEnumField("inst3", default=0xff, enum=_instructions),
        ByteEnumField("inst4", default=0xff, enum=_instructions),
        IntegerField("source_ts", default=time.time_ns() % (2**48), sz=6),
        ShortField("source_port", default=0),
        ConditionalField(ShortField("verif_isd", default=1), lambda pkt: pkt.verifier == 0),
        ConditionalField(AsnField("verif_asn", default="ff00:0:1"), lambda pkt: pkt.verifier == 0),
        ConditionalField(MultipleTypeField([
            (IPField("verif_host", default="127.0.0.1"),
             lambda pkt: pkt.vt == 0 and pkt.vl == 4),
            (IP6Field("verif_host", default="::1"),
             lambda pkt: pkt.vt == 0 and pkt.vl == 16)],
            XStrLenField("verif_host", default=None, length_from=lambda pkt: pkt.vl)
        ), lambda pkt: pkt.verifier == 0),
        PacketListField("stack", default=[], length_from=lambda pkt: 4*pkt.stack_len,
            pkt_cls=scion._detect_hbh_option_type)
    ]

    def self_build(self) -> bytes:
        if self.stack_len is None:
            self.stack_len = self.stack_length() // 4
        else:
            n = self.stack_length() // 4
            if n < self.stack_len:
                m = self.stack_len - n
                self.stack.append(scion.PadNOption(data=(4 * m - 2) * b"\x00"))

        if self.tos is None:
            tos = self.stack_entries() - 1
            tos_offset = 0
            if tos >= 0:
                for opt in self.stack[:tos]:
                    tos_offset += opt.length()
            self.tos = tos_offset // 4

        return super().self_build()

    def post_build(self, hdr: bytes, payload: bytes):
        if self.data_len is None:
            hdr_len = 22
            if self.verifier == 0:
                hdr_len += 8 + self.vl
            hdr = hdr[:1] + hdr_len.to_bytes(1, byteorder='big') + hdr[2:]
        return hdr + payload

    def stack_length(self) -> int:
        """Returns the allocated length of the telemetry stack in bytes."""
        length = 0
        for opt in self.stack:
            if type(opt) == IdIntEntry:
                length += opt.length()
            else:
                length += len(bytes(opt))
        return length

    def stack_entries(self) -> int:
        """Returns the number of telemetry stack entries."""
        count = 0
        while count < len(self.stack) and type(self.stack[count]) == IdIntEntry:
            count += 1
        return count

    def verify(self, keys: List[bytes], update: bool = False) -> None:
        """Computes the metadata MACs. Raises VerificationError if an incorrect
        MAC is encountered unless `update` is set.

        ### Parameters
        keys: AES-128 keys for AES-CMAC computation in source to sink order.
        update: Overwrite the current MACs with the correct ones. No MAC errors
            are reported.

        ### Exceptions
        VerificationError: Metadata verification failed.
        """
        entries = self.stack_entries()
        if entries == 0:
            return
        if len(keys) < entries:
            raise ValueError("Not enough keys")

        # Source
        mac = self.stack[0].calc_source_mac(self, keys[0])
        if update:
            self.stack[0].mac = mac
        elif self.stack[0].mac != mac:
            raise IdIntOption.VerificationError()

        # Transit hops
        for md, key in zip(self.stack[1:entries], keys[1:]):
            mac = md.calc_mac(mac, key)
            if update:
                md.mac = mac
            elif md.mac != mac:
                raise IdIntOption.VerificationError()


# Bind to SCION HBH extension header
scion.add_hbh_option_type(IdIntMainOptType, IdIntOption)
scion.add_hbh_option_type(IdIntEntryOptType, IdIntEntry)
