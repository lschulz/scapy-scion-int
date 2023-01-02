"""
SCION Telemetry Extension
"""

import copy
from array import array
from typing import Callable, List, Optional, Tuple

from scapy.error import warning
from scapy.fields import (BitEnumField, BitField, BitFieldLenField, ByteField,
                          Field, FieldLenField, FlagsField, MultiFlagsEntry,
                          MultiFlagsField, PacketListField, ShortField,
                          XShortField, XStrFixedLenField)
from scapy.packet import Packet

from . import scion

# Instructions which are always available
FixedInstructions = [
    ((7 - 0), 2, "NodeID", "Node ID"),
    ((7 - 1), 2, "NodeCnt", "Aggregated node count"),
    ((7 - 2), 6, "InTime", "Ingress timestamp"),
    ((7 - 3), 6, "EgTime", "Egress timestamp"),
    ((7 - 4), 4, "InIf", "Ingress interface"),
    ((7 - 5), 4, "EgIf", "Egress interface"),
    ((7 - 6), 4, "HopLat", "Hop latency"),
    ((7 - 7), 4, "TxLinkUtil", "Tx link utilization"),
]

# Instructions planes selected by a header field
VarInstructions = [
    # Plane 0: Reserved
    [((7 - i), 4, "R_0_%d" % i, "Reserved_0_%d" % i) for i in range(8)],
    # Plane 1: Metadata according to INT specification
    [
        ((7 - 0), 4, "INT_NodeID", "INT Node ID"),
        ((7 - 1), 4, "INT_L1If", "INT Level 1 interfaces"),
        ((7 - 2), 4, "INT_HopLat", "INT Hop latency"),
        ((7 - 3), 4, "INT_Queue", "INT Queue ID & occupancy"),
        ((7 - 4), 8, "INT_InTime", "INT Ingress timestamp"),
        ((7 - 5), 8, "INT_EgTime", "INT Egress timestamp"),
        ((7 - 6), 8, "INT_L2If", "INT Level 2 interfaces"),
        ((7 - 7), 4, "INT_EgTx", "INT Egress interface Tx utilization"),
    ],
    # Plane 2: Metadata according to INT specification (cont.)
    [
        ((7 - 0), 4, "INT_Buf", "INT Buffer ID & occupancy"),
        ((7 - 1), 4, "R_2_1", "Reserved_2_1"),
        ((7 - 2), 4, "R_2_2", "Reserved_2_2"),
        ((7 - 3), 4, "R_2_3", "Reserved_2_3"),
        ((7 - 4), 4, "R_2_4", "Reserved_2_4"),
        ((7 - 5), 4, "R_2_5", "Reserved_2_5"),
        ((7 - 6), 4, "R_2_6", "Reserved_2_6"),
        ((7 - 7), 4, "INT_Chksum", "INT Checksum complement")
    ],
]
# Plane 3-15: Reserved
for i in range(13):
    VarInstructions.append(
        [((7 - j), 4, "R_%d_%d" % (i, j), "Reserved_%d_%d" % (i, j)) for j in range(8)]
    )


class Instruction:
    """Identifier for an instruction from both the fixed and variable set.

    Stored a tuple of instruction plane (None for instructions from the fixed set) number and
    instruction number. Plane and instruction number are indices into the FixedInstructions and
    VarInstructions lists.
    """
    _InstNameToKey = {}
    for i, (_, _, name, _) in enumerate(FixedInstructions):
        _InstNameToKey[name] = (None, i)
    for sel, plane in enumerate(VarInstructions):
        for i, (_, _, name, _) in enumerate(plane):
            _InstNameToKey[name] = (sel, i)

    def __init__(self, *args):
        if len(args) == 2:
            self.sel = args[0]
            self.inst = args[1]
        elif isinstance(args[0], int):
            self.sel = None
            self.inst = args[0]
        elif isinstance(args[0], tuple):
            self.sel = args[0][0]
            self.inst = args[0][1]
        elif isinstance(args[0], str):
            self.sel, self.inst = self._InstNameToKey[args[0]]

    def __lt__(self, other):
        self_sel = self.sel or -1
        other_sel = other.sel or -1
        return (self_sel, self.inst) < (other_sel, other.inst)

    def __repr__(self):
        return "Instruction({}, {})".format(self.sel, self.inst)

    def __str__(self):
        return self.get_tuple()[2]

    def get_metadata_len(self):
        return self.get_tuple()[1]

    def get_mask_bit(self):
        if self.sel is None:
            return FixedInstructions[self.inst][0]
        else:
            return VarInstructions[self.sel][self.inst][0] + 8

    def get_tuple(self):
        if self.sel is None:
            return FixedInstructions[self.inst]
        else:
            return VarInstructions[self.sel][self.inst]


class Metadata:
    """A set of metadata as reported by a telemetry node."""

    global_metadata_plane = None

    def __init__(self, data: List[Tuple[Instruction, int]] = []):
        self.data = data

    @staticmethod
    def from_any_repr(pkt, repr):
        if repr is None:
            return Metadata([])
        elif isinstance(repr, Metadata):
            return copy.deepcopy(repr)
        elif isinstance(repr, dict):
            repr = repr.items()

        data = []
        for key, value in repr:
            if not isinstance(key, Instruction):
                key = Instruction(key)
            data.append((key, value))

        data.sort(key=lambda x: x[0])

        return Metadata(data)

    @staticmethod
    def parse(raw: bytes, mask: int, field_len: int) -> Tuple['Metadata', int]:
        """Read metadata from raw bytes according to set bits in the packet's metadata mask.

        Parameters:
        raw      : Raw byte string.
        mask     : Metadata bitmask determining which metadata is available in the byte string.
        field_len: Maximum number of bytes to read.

        Returns a tuple the parsed metadata and the number of bytes actually read.
        """
        data = []
        i = 0

        for key, (bit, length, _, _) in enumerate(FixedInstructions):
            if mask & (1 << bit):
                value, i = Metadata._extract_metadatum(raw, i, length, field_len)
                data.append((Instruction(None, key), value))

        inst_plane = Metadata.global_metadata_plane
        for key, (bit, length, _, _) in enumerate(VarInstructions[inst_plane]):
            if mask & (1 << (bit + 8)):
                value, i = Metadata._extract_metadatum(raw, i, length, field_len)
                data.append((Instruction(inst_plane, key), value))

        return (Metadata(data), i)

    @staticmethod
    def _extract_metadatum(raw: bytes, cursor: int, length: int, field_len: int) -> int:
        if cursor + length > field_len:
            warning("Telemetry report corrupted:" +
                " Less metadata than suggested by presence mask.")
            return (-1, cursor)
        else:
            return (
                int.from_bytes(raw[cursor:cursor+length], byteorder='big'),
                cursor + length)

    def __str__(self):
        return ";".join("{}={}".format(str(inst), val) for inst, val in self.data)

    def length(self) -> int:
        length = sum(inst.get_metadata_len() for inst, _ in self.data)
        return length

    def to_machine_repr(self) -> bytes:
        m = array("B")
        for key, value in self.data:
            length = key.get_metadata_len()
            m.extend(value.to_bytes(length, byteorder='big'))
        return m.tobytes()

    def get_mask(self) -> int:
        """Returns a bitmask describing which metadata are in this set."""
        mask = 0
        for inst, _ in self.data:
            mask |= (1 << inst.get_mask_bit())
        return mask


class MetadataField(Field[Metadata, bytes]):
    """Wraps Metadata into a Field with padding to keep the length a multiple of 4 bytes."""

    __slots__ = ["length_from"]

    def __init__(self, name, default, length_from: Callable[[Packet], int]):
        super().__init__(name, default)
        self.length_from = length_from

    def any2i(self, pkt, x):
        return Metadata.from_any_repr(pkt, x)

    def i2h(self, pkt, i):
        return i

    def i2repr(self, pkt, i) -> str:
        return str(i)

    def i2len(self, pkt, i) -> int:
        # Round up to a multiple of 4
        return (i.length() + 3) & ~0x03

    def i2m(self, pkt, i):
        m = i.to_machine_repr()
        padding = self._calc_padding(len(m))
        return m + padding * b"\x00"

    def m2i(self, pkt, m: bytes):
        return Metadata.parse(m, pkt.MetadataMask, self.length_from(pkt))[0]

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s: bytes):
        # Parse metadata
        metadata, bytes_read = Metadata.parse(s, pkt.MetadataMask, self.length_from(pkt))
        # Extract padding
        padding = self._calc_padding(bytes_read)
        return (s[bytes_read + padding:], metadata)

    def _calc_padding(self, length):
        return (4 - length & 0x03) & 0x03


class Report(Packet):
    """Telemetry report containing a variable amount of metadata."""

    name = "Report"

    fields_desc = [
        FlagsField("Flags", default=0, size=4, names={
            2**(3 - 0): "Ingress",
            2**(3 - 1): "Egress",
            2**(3 - 2): "Aggregated",
            2**(3 - 3): "Reserved",
        }),
        BitField("Hop", default=0, size=6),
        BitFieldLenField("Length", default=None, size=6, length_of="Metadata",
            adjust=lambda pkt, x: x // 4),
        XShortField("MetadataMask", default=None),
        ShortField("Reserved", default=0),
        XStrFixedLenField("Authentication", default=6*b"\x00", length=6),
        MetadataField("Metadata", default=[], length_from=lambda pkt: 4*pkt.Length)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s

    def post_build(self, hdr: bytes, payload: bytes):
        if self.MetadataMask is None:
            mask = self.Metadata.get_mask()
            hdr = hdr[:2] + mask.to_bytes(2, byteorder='big') + hdr[4:]

        return hdr + payload


class TelemetryOption(Packet):
    """SCION hop-by-hop option header for in-band telemetry."""

    name = "Telemetry"

    fields_desc = [
        ByteField("OptType", default=253),
        FieldLenField("OptDataLen", default=None, fmt="B", length_of="Hops",
            adjust=lambda pkt, x: x + 6),
        BitField("Version", default=0, size=3),
        FlagsField("Flags", default=0, size=5, names={
            2**(4 - 0): "Discard",
            2**(4 - 1): "Max hop count exceeded",
            2**(4 - 2): "MTU exceeded",
            2**(4 - 3): "Reserved_1",
            2**(4 - 4): "Reserved_2"
        }),
        BitEnumField("AggregationMode", default=0, size=2, enum={
            0: "Off",
            1: "AS",
            2: "Border",
            3: "Internal"
        }),
        BitField("RemainingHopCount", default=63, size=6),
        BitField("VarInstPlane", default=0, size=4),
        BitField("Reserved", default=0, size=4),
        FlagsField("FixedInst", default=0, size=8,
            names={2**bit: name for bit, _, name, _ in FixedInstructions}),
        MultiFlagsField("VarInst", default=0, size=8, depends_on=lambda pkt: pkt.VarInstPlane,
            names={
                id: {bit: MultiFlagsEntry(name, long_name) for bit, _, name, long_name in plane}
                    for id, plane in enumerate(VarInstructions)
            }
        ),
        ByteField("Reserved2", default=0),
        PacketListField("Hops", default=[], pkt_cls=Report,
            length_from=lambda pkt: pkt.OptDataLen - 6)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s

    def pre_dissect(self, s):
        # Extract the active metadata plane before 'Hops' are parsed.
        # Hack: Use a class variable to communicate the active metadata plane to Metadata and
        # MetadataField.
        Metadata.global_metadata_plane = (s[4] >> 4)
        return s


scion.add_hbh_option_type(253, TelemetryOption)
