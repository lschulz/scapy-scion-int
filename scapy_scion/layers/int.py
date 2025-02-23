"""
In-band Network Telemetry
https://p4.org/specs/
"""

from array import array
from typing import Any, List, Optional, Tuple, Union

from scapy.error import warning
from scapy.fields import (
    BitEnumField, BitField, ByteField, Field, FieldListField, FlagsField,
    PacketField, ShortField
)
from scapy.packet import Packet, bind_layers

from scapy_scion.layers.scion import UDP

# Instructions corresponding to standard metadata
# List of (bit, length (in bytes), name) tuples
_std_int_instructions = [
    ((15 -  0), 4, "Node ID"),
    ((15 -  1), 4, "Level 1 interfaces"),
    ((15 -  2), 4, "Hop latency"),
    ((15 -  3), 4, "Queue ID & occupancy"),
    ((15 -  4), 8, "Ingress timestamp"),
    ((15 -  5), 8, "Egress timestamp"),
    ((15 -  6), 8, "Level 2 interfaces"),
    ((15 -  7), 4, "Egress interface Tx utilization"),
    ((15 -  8), 4, "Buffer ID & occupancy"),
    ((15 -  9), 4, "Reserved_1"),
    ((15 - 10), 4, "Reserved_2"),
    ((15 - 11), 4, "Reserved_3"),
    ((15 - 12), 4, "Reserved_4"),
    ((15 - 13), 4, "Reserved_5"),
    ((15 - 15), 4, "Reserved_6"),
    ((15 - 15), 4, "Checksum complement")
]

_InstNameToKey = {name: key for key, (_, _, name) in enumerate(_std_int_instructions)}


class INTMetadataField(Field[List[Tuple[int, int]], bytes]):
    """A hop entry in the INT metadata stack.

    Every transit hop entry contains Hop ML * 4 bytes of metadata. The first hop
    entry at the bottom of the stack might contain additional source-only
    metadata (not supported by this implementation).

    The kind of metadata in an entry on the metadata stack depends on the bits
    set in the instruction bitmap and on domain-specific instructions.
    Domain-specific metadata is ignored by this class.

    Internally, metadata is represented as a list of (key, value) tuples, where
    key is the index into the '_std_int_instructions' array and value is the
    metadata as an integer.
    """

    def h2i(self, pkt, h: List[Tuple[Union[int, str], int]]):
        # Turn string keys into numerical keys
        i = map(lambda x: ((_InstNameToKey[x[0]] if isinstance(x[0], str) else x[0]), x[1]), h)
        i = list(i)

        # Check whether exactly the requested metadata is provided.
        if pkt is not None:
            instructions = pkt.instr_bitmap.value
            for key, (bit, _, name) in enumerate(_std_int_instructions):
                required = instructions & (1 << bit)
                provided = (key in (x[0] for x in i))
                if required and not provided:
                    i.append((key, 0))
                elif provided and not required:
                    warning("'{}' metadata is provided, but is not requested by the instruction"
                        + " bitmap.".format(name))

        # Make sure the internal list is sorted
        i.sort(key=lambda x: x[0])

        return i

    def any2i(self, pkt, x: Any):
        if isinstance(x, dict):
            return self.h2i(pkt, x.items())
        else:
            return self.h2i(pkt, x)

    def i2h(self, pkt, i) -> List[Tuple[Union[int, str], int]]:
        return [(_std_int_instructions[key][2], value) for key, value in i]

    def i2repr(self, pkt, i) -> str:
        h = self.i2h(pkt, i)
        return "\n" + " ".join("{}={}".format(k, v) for k, v in h)

    def i2m(self, pkt, i):
        m = array("B")
        for key, value in i:
            length = _std_int_instructions[key][1]
            m.extend(value.to_bytes(length, byteorder='big'))
        return m.tobytes()

    def m2i(self, pkt, m: bytes) :
        i, _ = self._parse(pkt, m)
        return i

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s: bytes):
        i, bytes_read = self._parse(pkt, s)
        return (s[bytes_read:], i)

    def _parse(self, pkt, raw: bytes) -> Tuple[List[Tuple[int, int]], int]:
        """Parse raw bytes to the internal list representation.
        Returns a tuple of the internal representation and the number of bytes
        read from 'raw'.
        """
        data: List[Tuple[int, int]] = []
        instructions = pkt.instr_bitmap.value
        i = 0

        # Parse standard metadata
        for key, (bit, length, _) in enumerate(_std_int_instructions):
            if instructions & (1 << bit):
                value = int.from_bytes(raw[i:i+length], byteorder='big')
                data.append((key, value))
                i += length

        # Skip over domain-specific metadata
        ds_metadata_len = 4 * pkt.hop_ml - i
        i += ds_metadata_len

        return (data, i)


class INToverUDPShim(Packet):
    """Shim header for embedding telemetry data in UDP packets."""

    name = "Shim header"

    fields_desc = [
        BitEnumField("type", default="md", size=4, enum={
            1: "md",
            2: "destination",
            3: "mx"
        }),
        BitEnumField("next_protocol", default="original_payload", size=2, enum={
            1: "original_payload",
            2: "original_header"
        }),
        BitField("reserved", default=0, size=2),
        ByteField("length", default=None),
        ShortField("original_dport", default=0)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class INT(Packet):
    """INT-MD over UDP with shim header"""

    name = "INT-MD"

    fields_desc = [
        PacketField("shim", default=INToverUDPShim(), pkt_cls=INToverUDPShim),
        BitField("version", default=2, size=4),
        FlagsField("flags", default=0, size=3, names={
            2**(2 - 0): "discard",
            2**(2 - 1): "hop_cnt_exceeded",
            2**(2 - 2): "mtu_exceeded"
        }),
        BitField("reserved", default=0, size=12),
        BitField("hop_ml", default=None, size=5),
        ByteField("rem_hop_cnt", default=255),
        FlagsField("instr_bitmap", default=0, size=16,
            names={2**bit: name for bit, _, name in _std_int_instructions}),
        ShortField("domain_specific_id", default=0),
        ShortField("ds_instr", default=0),
        ShortField("ds_flags", default=0),
        FieldListField("metadata", default=[],
            field=INTMetadataField("hop", default=[]),
            length_from=lambda pkt: 4 * pkt.shim.length - 12)
    ]

    def post_build(self, hdr: bytes, payload: bytes):
        hop_ml = None

        if self.shim.length is None:
            if hop_ml is None:
                hop_ml = self._calc_hop_ml_bytes()
            length = (len(self.metadata) * hop_ml + 12) // 4
            hdr = hdr[:1] + length.to_bytes(1, byteorder='big') + hdr[2:]

        if self.hop_ml is None:
            if hop_ml is None:
                hop_ml = self._calc_hop_ml_bytes()
            old_byte = int(hdr[6])
            new_byte = ((old_byte & 0xe0) | ((hop_ml // 4) & 0x1f)).to_bytes(1, byteorder='big')
            hdr = hdr[:6] + new_byte + hdr[7:]

        return hdr + payload

    def _calc_hop_ml_bytes(self) -> int:
        """Calculate the number of bytes added by each transit hop from the bits
        set in the instruction bitmap.
        """
        bitmap = self.instr_bitmap.value
        total_length = 0
        for bit, length, _ in _std_int_instructions:
            if bitmap & (1 << bit):
                total_length += length
        return total_length


bind_layers(UDP, INT, dport=51000)
