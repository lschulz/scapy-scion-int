"""
In-band Network Telemetry
https://p4.org/specs/
"""

from array import array
from typing import Any, List, Optional, Tuple, Union

from scapy.error import warning
from scapy.fields import (BitEnumField, BitField, BitScalingField, ByteField,
                          Field, FieldListField, FlagsField, PacketField,
                          ScalingField, ShortField)
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers


# Instructions corresponding to standard metadata
# List of (bit, length (in bytes), name) tuples
StdInstructions = [
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

_InstNameToKey = {name: key for key, (_, _, name) in enumerate(StdInstructions)}


class INTMetadataField(Field[List[Tuple[int, int]], bytes]):
    """A hop entry in the INT metadata stack.

    Every transit hop entry contains Hop ML * 4 bytes of metadata. The first hop entry at the bottom
    of the stack might contain additional source-only metadata (currently not supported by this
    implementation).

    The kind of metadata in an entry on the metadata stack depends on the bits set in the
    instruction bitmap and on domain-specific instructions. Domain-specific metadata is ignored
    by this class.

    Internally, metadata is represented as a list of (key, value) tuples, where key is the index
    into the 'StdInstructions' array and value is the metadata as an integer.
    """

    def h2i(self, pkt, h: List[Tuple[Union[int, str], int]]):
        # Turn string keys into numerical keys
        i = map(lambda x: ((_InstNameToKey[x[0]] if isinstance(x[0], str) else x[0]), x[1]), h)
        i = list(i)

        # Check whether exactly the requested metadata is provided.
        if pkt is not None:
            instructions = pkt.InstructionBitmap.value
            for key, (bit, _, name) in enumerate(StdInstructions):
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
        return [(StdInstructions[key][2], value) for key, value in i]

    def i2repr(self, pkt, i) -> str:
        h = self.i2h(pkt, i)
        return "\n" + " ".join("{}={}".format(k, v) for k, v in h)

    def i2m(self, pkt, i):
        m = array("B")
        for key, value in i:
            length = StdInstructions[key][1]
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
        Returns a tuple of the internal representation and the number of bytes read from 'raw'.
        """
        data: List[Tuple[int, int]] = []
        instructions = pkt.InstructionBitmap.value
        i = 0

        # Parse standard metadata
        for key, (bit, length, _) in enumerate(StdInstructions):
            if instructions & (1 << bit):
                value = int.from_bytes(raw[i:i+length], byteorder='big')
                data.append((key, value))
                i += length

        # Skip over domain-specific metadata
        ds_metadata_len = pkt.HopML - i
        i += ds_metadata_len

        return (data, i)


class INToverUDPShim(Packet):
    """Shim header for embedding telemetry data in UDP packets."""

    name = "Shim header"

    fields_desc = [
        BitEnumField("Type", default="MD", size=4, enum={
            1: "MD",
            2: "Destination",
            3: "MX"
        }),
        BitEnumField("NextProtocolType", default="OriginalPayload", size=2, enum={
            1: "OriginalPayload",
            2: "OriginalHeader"
        }),
        BitField("Reserved", default=0, size=2),
        ScalingField("Length", default=-1, fmt="B", scaling=4, unit="bytes"),
        ShortField("OriginalDstPort", default=0)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class INT(Packet):
    """INT-MD over UDP with shim header"""

    name = "INT-MD"

    fields_desc = [
        PacketField("Shim", default=INToverUDPShim(), pkt_cls=INToverUDPShim),
        BitField("Version", default=2, size=4),
        FlagsField("Flags", default=0, size=3, names={
            (2 - 0): "Discard",
            (2 - 1): "Max Hop Count exceeded",
            (2 - 2): "MTU exceeded"
        }),
        BitField("Reserved", default=0, size=12),
        BitScalingField("HopML", default=-1, size=5, scaling=4, unit="bytes"),
        ByteField("RemainingHopCount", default=255),
        FlagsField("InstructionBitmap", default=0, size=16,
            names={bit: name for bit, _, name in StdInstructions}),
        ShortField("DomainSpecificID", default=0),
        ShortField("DSInstructions", default=0),
        ShortField("DSFlags", default=0),
        FieldListField("Metadata", default=[],
            field=INTMetadataField("Hop", default=[]),
            length_from=lambda pkt: pkt.Shim.Length - 12)
    ]

    def post_build(self, hdr: bytes, payload: bytes):
        hop_ml = None

        if self.Shim.Length < 0:
            if hop_ml is None:
                hop_ml = self._calc_hop_ml()
            length = (len(self.Metadata) * hop_ml + 12) // 4
            hdr = hdr[:1] + length.to_bytes(1, byteorder='big') + hdr[2:]

        if self.HopML < 0:
            if hop_ml is None:
                hop_ml = self._calc_hop_ml()
            old_byte = int(hdr[6])
            new_byte = ((old_byte & 0xe0) | ((hop_ml // 4) & 0x1f)).to_bytes(1, byteorder='big')
            hdr = hdr[:6] + new_byte + hdr[7:]

        return hdr + payload

    def _calc_hop_ml(self) -> int:
        """Calculate the number of bytes added by each transit hop from the bits set in the
        instruction bitmap.
        """
        bitmap = self.InstructionBitmap.value
        total_length = 0
        for bit, length, _ in StdInstructions:
            if bitmap & (1 << bit):
                total_length += length
        return total_length


bind_layers(UDP, INT, dport=51000)
