"""
Inter-Domain In-band Network Telemetry for SCION
https://github.com/netsys-lab/id-int-spec
"""

import time
from typing import Callable, List, Optional, Tuple

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from scapy.fields import (BitEnumField, BitField, BitScalingField,
                          ByteEnumField, ConditionalField, Field,
                          FieldLenField, FlagsField, IntField, IP6Field,
                          IPField, MultipleTypeField, PacketListField,
                          ShortField, StrLenField, XStrFixedLenField,
                          XStrLenField)
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers

from scapy_scion.fields import AsnField, IntegerField
from scapy_scion.layers import scion


FixedInst = {
    (3 - 0): "NodeID",
    (3 - 1): "NodeCnt",
    (3 - 2): "InIf",
    (3 - 3): "EgIf"
}

VarInst = {
    0x00: "ZERO_2",
    0x01: "ISD",
    0x02: "BR_LINK_TYPE",
    0x03: "DEVICE_TYPE_ROLE",
    0x04: "CPU_MEM_USAGE",
    0x05: "CPU_TEMP",
    0x06: "ASIC_TEMP",
    0x07: "FAN_SPEED",
    0x08: "TOTAL_POWER",
    0x09: "ENERGY_MIX",
    0x40: "ZERO_4",
    0x41: "DEVICE_VENDOR",
    0x42: "DEVICE_MODEL",
    0x43: "SOFTWARE_VERSION",
    0x44: "NODE_IPV4_ADDR",
    0x45: "INGRESS_IF_SPEED",
    0x46: "EGRESS_IF_SPEED",
    0x47: "UPTIME",
    0x48: "FWD_ENERGY",
    0x49: "CO2_EMISSION",
    0x4A: "INGRESS_LINK_RX",
    0x4B: "EGRESS_LINK_TX",
    0x4C: "QUEUE_ID",
    0x4D: "INST_QUEUE_LEN",
    0x4E: "AVG_QUEUE_LEN",
    0x4F: "BUFFER_ID",
    0x50: "INST_BUFFER_OCC",
    0x51: "AVG_BUFFER_OCC",
    0x80: "ZERO_6",
    0x81: "ASN",
    0x82: "INGRESS_TSTAMP",
    0x83: "EGRESS_TSTAMP",
    0x84: "IG_SCIF_PKT_CNT",
    0x85: "EG_SCIF_PKT_CNT",
    0x86: "IG_SCIF_PKT_DROP",
    0x87: "EG_SCIF_PKT_DROP",
    0x88: "IG_SCIF_BYTES",
    0x89: "EG_SCIF_BYTES",
    0x8A: "IG_PKT_CNT",
    0x8B: "EG_PKT_CNT",
    0x8C: "IG_PKT_DROP",
    0x8D: "EG_PKT_DROP",
    0x8E: "IG_BYTES",
    0x8F: "EG_BYTES",
    0xC0: "ZERO_8",
    0xC1: "NODE_IPV6_ADDR_H",
    0xC2: "NODE_IPV6_ADDR_L",
    0xC3: "GPS_LAT",
    0xC4: "GPS_LONG",
    0xFF: "NOP"
}

AggrFunctions = {
    0: "First",
    1: "Last",
    2: "Minimum",
    3: "Maximum",
    4: "Sum"
}


class MetadataLenField(BitField):
    """Length field for variable size metadata.

    The internal representation is an integer number of bytes, the machine representation is encoded
    as follows:
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
        return self._padwith[:padding]

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, bytes]:
        padding = s[:self.padlen(pkt)]
        return (s[len(padding):], padding)

    def addfield(self, pkt: Packet, s: bytes, val: bytes) -> bytes:
        return s + self.i2m(pkt, val)


class Metadata(Packet):
    """Entry on the ID-INT metadata stack"""

    name = "Metadata"

    fields_desc = [
        FlagsField("Flags", default=0, size=5, names={
            (4 - 0): "Source",
            (4 - 1): "Ingress",
            (4 - 2): "Egress",
            (4 - 3): "Aggregate",
            (4 - 4): "Encrypted"
        }),
        BitField("Reserved1", default=0, size=3),
        BitField("Hop", default=0, size=6),
        BitField("Reserved2", default=0, size=2),
        FlagsField("Mask", default=0, size=4, names=FixedInst),
        MetadataLenField("ML1", length_of="MD1"),
        MetadataLenField("ML2", length_of="MD2"),
        MetadataLenField("ML3", length_of="MD3"),
        MetadataLenField("ML4", length_of="MD4"),
        ConditionalField(XStrFixedLenField("Nonce", default=12*b"\x00", length=12),
            lambda pkt: pkt.Flags.Encrypted),
        ConditionalField(IntField("NodeID", default=0), lambda pkt: pkt.Mask.NodeID),
        ConditionalField(ShortField("NodeCnt", default=0), lambda pkt: pkt.Mask.NodeCnt),
        ConditionalField(ShortField("InIf", default=0), lambda pkt: pkt.Mask.InIf),
        ConditionalField(ShortField("EgIf", default=0), lambda pkt: pkt.Mask.EgIf),
        StrLenField("MD1", default=b"", length_from=lambda pkt: pkt.ML1),
        StrLenField("MD2", default=b"", length_from=lambda pkt: pkt.ML2),
        StrLenField("MD3", default=b"", length_from=lambda pkt: pkt.ML3),
        StrLenField("MD4", default=b"", length_from=lambda pkt: pkt.ML4),
        MetadataPadField("Padding", 4, length_from=lambda pkt: Metadata._get_md_len(pkt)),
        XStrFixedLenField("MAC", default=b"\x00\x00\x00\x00", length=4)
    ]

    @staticmethod
    def _get_md_len(pkt):
        """Returns the length of the metadata fields in bytes."""
        length = 0
        length += 4 if pkt.Mask.NodeID else 0
        length += 2 if pkt.Mask.NodeCnt else 0
        length += 2 if pkt.Mask.InIf else 0
        length += 2 if pkt.Mask.EgIf else 0
        length += len(pkt.MD1) + len(pkt.MD2) + len(pkt.MD3) + len(pkt.MD4)
        return length

    def source_mac(self, hdr: "IDINT", key: bytes) -> bytes:
        """Compute the MAC for the source hop.
        :param hdr: IDINT main header. The source MAC includes fields from the main header.
        :param key: AES-128 key for AES-MAC computation.
        :returns: 4-byte MAC
        """
        c = cmac.CMAC(algorithms.AES(key))
        hdr = hdr.copy()
        hdr.Length = 0
        hdr.NextHdr = 0
        hdr.DelayHops = 0
        hdr.RemHops = 0
        hdr.Metadata = []
        hdr.remove_payload()
        c.update(bytes(hdr))
        c.update(bytes(self)[:-4])
        return c.finalize()[:4]

    def mac(self, prev_mac: bytes, key: bytes) -> bytes:
        """Compute the metadata MAC.
        :param prev_mac: MAC of the previous stack entry.
        :param key: AES-128 key for AES-MAC computation.
        :returns: 4-byte MAC
        """
        c = cmac.CMAC(algorithms.AES(key))
        c.update(bytes(self)[:-4])
        c.update(prev_mac)
        return c.finalize()[:4]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class IDINT(Packet):
    """ID-INT SCION extension header"""

    name = "ID-INT"

    class VerificationError(Exception):
        def __str__(self):
            return "IDINT metadata verification failed"

    fields_desc = [
        BitField("Version", default=0, size=3),
        FlagsField("Flags", default=0, size=5, names={
            (4 - 0): "Infrastructure",
            (4 - 1): "Discard",
            (4 - 2): "Encrypted",
            (4 - 3): "Hop count exceeded",
            (4 - 4): "Stack full"
        }),
        BitEnumField("AggrMode", default=0, size=2, enum={
            0: "Off",
            1: "AS",
            2: "Border",
            3: "Internal"
        }),
        BitEnumField("Verifier", default=1, size=2, enum={
            0: "ThirdParty",
            1: "Destination",
            2: "Source"
        }),
        BitEnumField("VT", default="IP", size=2, enum=scion.SCION.address_types),
        BitScalingField("VL", default=4, size=2, scaling=4, offset=4, unit="bytes"),
        FieldLenField("Length", default=None, fmt="B", length_of="Metadata",
            adjust=lambda pkt, x: x // 4),
        ByteEnumField("NextHdr", default=None, enum=scion.ProtocolNames),
        BitField("DelayHops", default=0, size=6),
        BitField("Reserved1", default=0, size=2),
        BitField("RemHops", default=63, size=6),
        BitField("Reserved2", default=0, size=2),
        FlagsField("InstFlags", default=0, size=4, names=FixedInst),
        BitEnumField("AF1", default=0, size=3, enum=AggrFunctions),
        BitEnumField("AF2", default=0, size=3, enum=AggrFunctions),
        BitEnumField("AF3", default=0, size=3, enum=AggrFunctions),
        BitEnumField("AF4", default=0, size=3, enum=AggrFunctions),
        ByteEnumField("Inst1", default=0xff, enum=VarInst),
        ByteEnumField("Inst2", default=0xff, enum=VarInst),
        ByteEnumField("Inst3", default=0xff, enum=VarInst),
        ByteEnumField("Inst4", default=0xff, enum=VarInst),
        IntegerField("SourceTS", default=time.time_ns() % (2**48), sz=6),
        ConditionalField(ShortField("SourcePort", default=0), lambda pkt: pkt.Verifier == 0),
        ConditionalField(ShortField("VerifISD", default=1), lambda pkt: pkt.Verifier == 0),
        AsnField("VerifAS", default="ff00:0:1"),
        ConditionalField(MultipleTypeField([
            (IPField("VerifAddr", default="127.0.0.1"),
             lambda pkt: pkt.VT == 0 and pkt.VL == 4),
            (IP6Field("VerifAddr", default="::1"),
             lambda pkt: pkt.VT == 0 and pkt.VL == 16)],
            XStrLenField("VerifAddr", default=None, length_from=lambda pkt: pkt.VL)
        ), lambda pkt: pkt.Verifier == 0),
        PacketListField("Metadata", default=[], pkt_cls=Metadata,
            length_from=lambda pkt: 4*pkt.Length)
    ]

    def verify(self, keys: List[bytes], update: bool = False) -> None:
        """Computes the metadata MACs. Raises IDINT.VerificationError if an incorrect MAC is
        encountered unless `update` is set.
        :param keys: AES-128 keys for AES-CMAC computation in source to sink order.
        :param update: Overwrite the current MACs with the correct ones. No MAC errors are reported.
        :raises: IDINT.VerificationError: Metadata verification failed.
        """
        if len(self.Metadata) == 0:
            return
        if len(keys) < len(self.Metadata):
            raise Exception("Not enough keys")
        # Source
        mac = self.Metadata[-1].source_mac(self, keys[0])
        if update:
            self.Metadata[-1].MAC = mac
        elif self.Metadata[-1].MAC != mac:
            raise IDINT.VerificationError()
        # Transit hops
        for md, key in zip(reversed(self.Metadata[:-1]), keys[1:]):
            mac = md.mac(mac, key)
            if update:
                md.MAC = mac
            elif md.MAC != mac:
                raise IDINT.VerificationError()


# Bind to SCION
bind_layers(scion.SCION, IDINT, NextHdr=scion.ProtocolNumbers["Experiment1"])

# Bind upper-layer protocols
# At the moment IDINT cannot be combined with SCION Hop-by-Hop and End-to-End extensions
bind_layers(IDINT, UDP, NextHdr=scion.ProtocolNumbers['UDP'])
