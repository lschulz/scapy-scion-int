import unittest

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from scapy_scion.layers.bfd import BFD
from scapy_scion.layers.scion import (SCION, UDP, AuthenticatorOption,
                                      EmptyPath, EndToEndExt, HopByHopExt,
                                      HopField, InfoField, PadNOption,
                                      ProtocolNumbers, SCIONPath)
from scapy_scion.layers.scmp import SCMP, ParameterProblem, SCIONerror


class TestSCION(unittest.TestCase):

    def test_dissect(self):
        """Test dissecting SCION packets"""

        # SCION/BFD
        packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00x&\xc3@\x00@\x11\x15\xa9\x7f\x00\x00\x05\x7f\x00\x00\x04\xc3P\xc3P\x00d\xfe~\x0b\x80\xde\xad\xcb\x11\x00\x18\x02\x00\x00\x00\x00\x01\xff\x00\x00\x00\x01\x10\x00\x01\xff\x00\x00\x00\x01\x11\x7f\x00\x00\x04\x7f\x00\x00\x05\x01\x00\x00\x00`\xb3\xe5a\x00?\x00\x00\x00)\xbb(\xac\xce\xf0\xac\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \xc0\x03\x18\x93LZ\x07\xa0\xcb\t\xba\x00\x03\r@\x00\x03\r@\x00\x00\x00\x00'
        p = Ether(packet)
        self.assertEqual(p.layers(), [Ether, IP, UDP, SCION, BFD])
        scion = p[SCION]
        self.assertEqual(scion.FlowID, 0xdead)
        self.assertEqual(scion.HdrLen, 68)
        self.assertEqual(scion.DstAS, "ff00:0:110")
        self.assertEqual(scion.SrcAS, "ff00:0:111")
        self.assertEqual(scion.DstHostAddr, "127.0.0.4")
        self.assertEqual(scion.SrcHostAddr, "127.0.0.5")
        self.assertEqual(scion.Path.getlayer(InfoField).SegID, 0x0)
        self.assertEqual(scion.Path.getlayer(HopField, 1).MAC, 0xbb28accef0ac)
        self.assertEqual(scion.Path.getlayer(HopField, 2).MAC, 0x0)
        bfd = p[BFD]
        self.assertEqual(bfd.getfieldval("MyDiscriminator"), 2471254535)

        # SCMP Echo Request
        packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00t@u@\x00@\x11\xfb\xfa\x7f\x00\x00\x04\x7f\x00\x00\x05\xc3P\xc3P\x00`\xfez\x00\x00\x00\x01\xca\x12\x00\x10\x01\x00\x00\x00\x00\x01\xff\x00\x00\x00\x01\x11\x00\x01\xff\x00\x00\x00\x01\x10\x7f\x00\x00\x01\x7f\x00\x00\x01\x01\x00 \x00\x01\x00K\xeb`\xb3\xe5l\x00?\x00\x00\x00\x01\x1cO\xa3\xfc\xf6\x86\x00?\x00)\x00\x00\xd8\xee\xea\xa0\xbf\x18\x80\x00\xbc\xd1\xc7\xd6\x00\x01\x16\x83\xeeg\x9dBZ&'
        p = Ether(packet)
        self.assertEqual(p.layers(), [Ether, IP, UDP, SCION, SCMP, Raw])
        scion = p[SCION]
        self.assertEqual(scion.FlowID, 0x1)
        self.assertEqual(scion.HdrLen, 72)
        self.assertEqual(scion.DstAS, "ff00:0:111")
        self.assertEqual(scion.SrcAS, "ff00:0:110")
        self.assertEqual(scion.DstHostAddr, "127.0.0.1")
        self.assertEqual(scion.SrcHostAddr, "127.0.0.1")
        self.assertEqual(scion.Path.getlayer(InfoField).SegID, 0x4beb)
        self.assertEqual(scion.Path.getlayer(HopField, 1).MAC, 0x1c4fa3fcf686)
        self.assertEqual(scion.Path.getlayer(HopField, 2).MAC, 0xd8eeeaa0bf18)
        scmp = p[SCMP]
        self.assertEqual(scmp.Type, scmp.TypeEchoRequest)
        self.assertEqual(scmp.Message.Identifier, 51158)

        # SCMP Parameter Problem
        packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00\x98@u@\x00@\x11\xfb\xfa\x7f\x00\x00\x04\x7f\x00\x00\x05\xc3P\xc3P\x00\x84\xfez\x00\x00\x00\x01\xca\x12\x004\x01\x00\x00\x00\x00\x01\xff\x00\x00\x00\x01\x11\x00\x01\xff\x00\x00\x00\x01\x10\x7f\x00\x00\x01\x7f\x00\x00\x01\x01\x00 \x00\x01\x00K\xeb`\xb3\xe5l\x00?\x00\x00\x00\x01\x1cO\xa3\xfc\xf6\x86\x00?\x00)\x00\x00\xd8\xee\xea\xa0\xbf\x18\x04\x11\xef:\x00\x00\x00\x00\x00\x00\x00\x01\x11\t\x00\x08\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00\x00\x01\x00\x01\xff\x00\x00\x00\x00\x02\x7f\x00\x00\x01\x7f\x00\x00\x01\x005\x005\x00\x08\x02\x1e'
        p = Ether(bytes(packet))
        self.assertEqual(p.layers(), [Ether, IP, UDP, SCION, SCMP, SCIONerror, UDP])
        scmp = p[SCMP]
        self.assertEqual(scmp.Type, scmp.TypeParameterProblem)
        self.assertEqual(scmp.Code, 17)
        self.assertEqual(scmp.Message.Pointer, 0)

        # SCION/UDP (OneHopPath)
        packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00h<\xfb@\x00@\x11\xff\x80\x7f\x00\x00\x04\x7f\x00\x00\x05\xc3P\xc3P\x00T\xfen\x00\x00\x00\x01\x11\x11\x00\x08\x02@\x00\x00\x00\x01\xff\x00\x00\x00\x01\x11\x00\x01\xff\x00\x00\x00\x01\x10\x00\x02\x00\x00\x7f\x00\x00\x0b\x01\x00\x9d\xaa`\xb3\xe5l\x00?\x00\x00\x00\x01I\x86\x17h\xd7\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xc8\x00\x00\x00\x08\xff\xe3'
        p = Ether(packet)
        self.assertEqual(p.layers(), [Ether, IP, UDP, SCION, UDP])
        scion = p[SCION]
        self.assertEqual(scion.FlowID, 0x1)
        self.assertEqual(scion.HdrLen, 68)
        self.assertEqual(scion.DstAS, "ff00:0:111")
        self.assertEqual(scion.SrcAS, "ff00:0:110")
        self.assertEqual(scion.DstHostAddr, b"\x00\x02\x00\x00")
        self.assertEqual(scion.SrcHostAddr, "127.0.0.11")
        self.assertEqual(scion.Path.getlayer(InfoField).SegID, 0x9daa)
        self.assertEqual(scion.Path.getlayer(HopField, 1).MAC, 0x49861768d715)
        self.assertEqual(scion.Path.getlayer(HopField, 2).MAC, 0x0)
        udp = scion[UDP]
        self.assertEqual(udp.chksum, 0xffe3)

    def test_build(self):
        """Test building SCION packets"""

        p = IP()/UDP()
        p = p/SCION(
            Path=SCIONPath(
                Seg0Len=2,
                InfoFields=[InfoField()],
                HopFields=[HopField(), HopField()]
            )
        )
        p = p/HopByHopExt(Options=[PadNOption()])
        p = p/EndToEndExt(Options=[PadNOption(OptData=b"\x00"), AuthenticatorOption()])
        p = p/SCMP()

        ip = IP(bytes(p))
        self.assertEqual(ip[UDP].sport, 30042)
        self.assertEqual(ip[UDP].dport, 30042)
        scion = ip[SCION]
        self.assertEqual(scion.NextHdr, ProtocolNumbers["HopByHopExt"])
        hbh = scion[HopByHopExt]
        self.assertEqual(hbh.ExtLen, 0)
        e2e = scion[EndToEndExt]
        self.assertEqual(e2e.ExtLen, 5)

    def test_scmp_checksum(self):
        """Test checksum update with SCMP payload."""

        packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00t@u@\x00@\x11\xfb\xfa\x7f\x00\x00\x04\x7f\x00\x00\x05\xc3P\xc3P\x00`\xfez\x00\x00\x00\x01\xca\x12\x00\x10\x01\x00\x00\x00\x00\x01\xff\x00\x00\x00\x01\x11\x00\x01\xff\x00\x00\x00\x01\x10\x7f\x00\x00\x01\x7f\x00\x00\x01\x01\x00 \x00\x01\x00K\xeb`\xb3\xe5l\x00?\x00\x00\x00\x01\x1cO\xa3\xfc\xf6\x86\x00?\x00)\x00\x00\xd8\xee\xea\xa0\xbf\x18\x80\x00\xff\xff\xc7\xd6\x00\x01\x16\x83\xeeg\x9dBZ&'

        original = Ether(packet)
        self.assertEqual(original[SCMP].Checksum, 0xffff)

        # Force recomputation of the checksum
        del original[SCION].HdrLen
        del original[SCMP].Checksum

        p = Ether(bytes(original))
        self.assertEqual(p[SCMP].Checksum, 0xbcd1)

    def test_udp_checksum(self):
        """Test checksum update with UDP payload."""

        packet = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00h<\xfb@\x00@\x11\xff\x80\x7f\x00\x00\x04\x7f\x00\x00\x05\xc3P\xc3P\x00T\xfen\x00\x00\x00\x01\x11\x11\x00\x08\x02@\x00\x00\x00\x01\xff\x00\x00\x00\x01\x11\x00\x01\xff\x00\x00\x00\x01\x10\x00\x02\x00\x00\x7f\x00\x00\x0b\x01\x00\x9d\xaa`\xb3\xe5l\x00?\x00\x00\x00\x01I\x86\x17h\xd7\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xc8\x00\x00\x00\x08\xff\xff'

        original = Ether(packet)
        self.assertEqual(original.getlayer(UDP, 2).chksum, 0xffff)

        # Force recomputation of the checksum
        del original[SCION].HdrLen
        del original[UDP].chksum

        p = Ether(bytes(original))
        self.assertEqual(p.getlayer(UDP, 2).chksum, 0xffe3)
