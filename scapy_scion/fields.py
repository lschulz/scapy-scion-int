"""
Special fields for SCION headers
"""

import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Optional, Union

from scapy.base_classes import Net
from scapy.fields import ByteField, Field, IntField
from scapy.volatile import RandField

from .scion_addr import ASN


class IntegerField(Field[int, bytes]):
    """Integer field with arbitrary fixed length in bytes."""

    def __init__(self, name: str, default: Optional[int], sz: int):
        Field.__init__(self, name, default, fmt=f"!{sz}s")

    def i2m(self, pkt, x) -> bytes:
        return x.to_bytes(length=self.sz, byteorder='big')

    def m2i(self, pkt, x) -> int:
        return int.from_bytes(x[:self.sz], byteorder='big')


class _RandAsn(RandField[ASN]):
    def _fix(self):
        return ASN(random.randint(0, ASN.MAX_VALUE))


class AsnField(Field[ASN, bytes]):
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

    def randval(self):
        return _RandAsn()


class _RandHostIP(RandField[bytes]):
    def _fix(self):
        return random.randint(0, (2**32)-1).to_bytes(4, byteorder="big")


class HostAddressField(Field[Union[IPv4Address, IPv6Address, bytes], bytes]):
    """SCION AS-internal host address"""

    __slots__ = ["type_from", "length_from"]

    def __init__(self, name: str, default: bytes, type_from: str, length_from: str):
        super().__init__(name, default, "I")
        self.type_from = type_from
        self.length_from = length_from

    def _isip(self, pkt):
        if pkt is not None:
            return pkt.getfieldval(self.type_from) == 0
        else:
            return True

    @staticmethod
    def i2len(pkt, x):
        if isinstance(x, (IPv4Address, IPv6Address)):
            return 4 if x.version == 4 else 16
        else:
            return len(x)

    def h2i(self, pkt, h):
        if self._isip(pkt):
            try:
                return ip_address(h)
            except ValueError:
                pass
        if not isinstance(h, bytes):
            raise ValueError("Expected bytes for field %s" % self.name)
        return h

    def i2repr(self, pkt, i) -> str:
        return str(self.i2h(pkt, i))

    def m2i(self, pkt, m: bytes):
        if self._isip(pkt):
            if len(m) == 4:
                return IPv4Address(m)
            elif len(m) == 16:
                return IPv6Address(m)
        return m

    def i2m(self, pkt, i) -> bytes:
        if isinstance(i, (IPv4Address, IPv6Address)):
            return i.packed
        return i

    def addfield(self, pkt, s, val) -> bytes:
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        fval = pkt.getfieldval(self.length_from)
        sz = 4 * fval + 4
        return (s[sz:], self.m2i(pkt, s[:sz]))

    def randval(self):
        return _RandHostIP()


class UnixTimestampField(IntField):
    """32 bit Unix timestamp with second resolution"""

    def h2i(self, pkt, h: datetime):
        return int(h.timestamp())

    def i2h(self, pkt, i) -> datetime:
        return datetime.fromtimestamp(i)

    def i2repr(self, pkt, i) -> str:
        return str(datetime.fromtimestamp(i))


class ExpiryTimeField(ByteField):
    """Hop fields expiry time relative to timestamp in info field"""

    def i2repr(self, pkt, i):
        rel = timedelta(seconds=(i + 1) * (24 * 60 * 60 / 256))
        return str(rel)
