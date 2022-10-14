"""
Special fields for SCION headers
"""

from datetime import datetime
from typing import Optional

from scapy.fields import ByteField, Field, IntField

from .scion_addr import ASN


class IntegerField(Field[int, bytes]):
    """Integer field with arbitrary fixed length in bytes."""

    def __init__(self, name: str, default: Optional[int], sz: int):
        Field.__init__(self, name, default, fmt=f"!{sz}s")

    def i2m(self, pkt, x) -> bytes:
        return x.to_bytes(length=self.sz, byteorder='big')

    def m2i(self, pkt, x) -> int:
        return int.from_bytes(x[:self.sz], byteorder='big')


class AsnField(Field):
    """SCION AS identifier (48 bits)"""

    def h2i(self, pkt, h):
        return ASN(h) if h is not None else h

    def i2h(self, pkt, i):
        return str(i) if i is not None else i

    def i2repr(self, pkt, i) -> str:
        return str(i)

    def m2i(self, pkt, m):
        return ASN.from_bytes(m)

    def i2m(self, pkt, i):
        return i.to_bytes()

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        return (
            s[6:],
            self.m2i(pkt, s[:6])
        )


class UnixTimestamp(IntField):
    """32 bit Unix timestamp with second resolution"""

    def h2i(self, pkt, h: datetime):
        return int(h.timestamp())

    def i2h(self, pkt, i) -> datetime:
        return datetime.fromtimestamp(i)

    def i2repr(self, pkt, i) -> str:
        return str(datetime.fromtimestamp(i))


class ExpiryTime(ByteField):
    """Hop fields expiry time"""

    def i2repr(self, pkt, i):
        rel_seconds = (i + 1) * (24 * 60 * 60 / 256)
        return "Relative: {} seconds".format(
            rel_seconds,
        )
