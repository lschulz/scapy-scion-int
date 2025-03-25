import unittest

from scapy.layers.inet import IP

from scapy_scion.layers.idint import IdIntEntry, IdIntOption, _cbcmac
from scapy_scion.layers.scion import (
    SCION, UDP, HopByHopExt, PadNOption, SCIONPath
)


class TestIDINT(unittest.TestCase):

    def test_stack_padding(self):
        """Test padding of the telemetry stack with PadN options"""

        p = IP()/UDP()/SCION(path=SCIONPath())
        p /= HopByHopExt(options=[
            IdIntOption(
                verifier="third_party",
                vt="IP",
                vl=4,
                inst_flags="node_id",
                inst1="ingress_tstamp",
                inst2="egress_tstamp",
                verif_isd=1000,
                verif_asn="ff00:0:100",
                stack_len = 32,
                stack = [
                    IdIntEntry(flags="source+egress", hop=0, mask="node_id",
                        node_id=1, md1=(1).to_bytes(4, 'big'), md2=(2).to_bytes(4, 'big')),
                ]
            )
        ])

        p = IP(bytes(p))
        opts = p[HopByHopExt].options
        self.assertEqual(len(opts), 1)
        self.assertIsInstance(opts[0], IdIntOption)
        self.assertEqual(opts[0].data_len, 34)
        self.assertEqual(opts[0].stack_len, 32)
        self.assertEqual(opts[0].tos, 0)

        stack = opts[0].stack
        self.assertIsInstance(stack[0], IdIntEntry)
        self.assertEqual(stack[0].data_len, 24)
        self.assertIsInstance(stack[1], PadNOption)
        self.assertEqual(stack[1].data_len, 102)

    def test_idint_verification(self):
        """Test ID-INT header verification"""

        p = IP()/UDP()/SCION(path=SCIONPath())
        p /= HopByHopExt(options=[
            IdIntOption(
                flags="discard",
                aggregation="as",
                verifier="third_party",
                vt="IP",
                vl=4,
                inst_flags="node_id",
                inst1="ingress_tstamp",
                inst2="device_type_role",
                source_port=10,
                verif_isd=1000,
                verif_asn="ff00:0:100",
                stack = [
                    IdIntEntry(flags="source+egress", hop=0, mask="node_id",
                        node_id=1, md1=(1).to_bytes(4, 'big'), md2=(2).to_bytes(2, 'big')),
                    IdIntEntry(flags="ingress+egress", hop=1, mask="node_id",
                        node_id=2, md1=(3).to_bytes(4, 'big'), md2=(4).to_bytes(2, 'big')),
                    IdIntEntry(flags="ingress", hop=2, mask="node_id",
                        node_id=3, md1=(5).to_bytes(4, 'big')),
                    PadNOption(data=b"\x00\x00")
                ]
            )
        ])

        keys = [
            16 * b"\x01",
            16 * b"\x02",
            16 * b"\x03"
        ]
        p = IP(bytes(p))
        p[IdIntOption].verify(keys, update=True)

        self.assertEqual(p.layers(), [IP, UDP, SCION, HopByHopExt])
        self.assertEqual(p[SCION].hlen, 40 // 4)
        idint = p[IdIntOption]
        idint.verify(keys)
        self.assertEqual(idint.flags.value, 0x08)
        self.assertEqual(idint.verif_isd, 1000)
        self.assertEqual(idint.verif_asn, "ff00:0:100")
        self.assertEqual(idint.verif_host, "127.0.0.1")
        stack = idint.stack
        self.assertEqual(len(stack), 4)
        self.assertEqual(stack[0].hop, 0)
        self.assertEqual(stack[0].ml1, 4)
        self.assertEqual(stack[0].ml2, 2)
        self.assertEqual(stack[0].ml3, 0)
        self.assertEqual(stack[0].ml4, 0)
        self.assertEqual(int.from_bytes(stack[0].md1, 'big'), 1)
        self.assertEqual(int.from_bytes(stack[0].md2, 'big'), 2)
        self.assertEqual(len(stack[0].padding), 0)
        self.assertEqual(stack[1].hop, 1)
        self.assertEqual(stack[1].ml1, 4)
        self.assertEqual(stack[1].ml2, 2)
        self.assertEqual(stack[1].ml3, 0)
        self.assertEqual(stack[1].ml4, 0)
        self.assertEqual(int.from_bytes(stack[1].md1, 'big'), 3)
        self.assertEqual(int.from_bytes(stack[1].md2, 'big'), 4)
        self.assertEqual(len(stack[1].padding), 0)
        self.assertEqual(stack[2].hop, 2)
        self.assertEqual(stack[2].ml1, 4)
        self.assertEqual(stack[2].ml2, 0)
        self.assertEqual(stack[2].ml3, 0)
        self.assertEqual(stack[2].ml4, 0)
        self.assertEqual(int.from_bytes(stack[2].md1, 'big'), 5)
        self.assertEqual(len(stack[2].padding), 2)


class TestCBCMAC(unittest.TestCase):
    """Test AES CBC-MAC calculation"""

    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10'
    data = bytes((2*i-1)%256 for i in range(32))

    def test_mac_16b(self):
        mac = _cbcmac(self.data[:16], self.key)
        self.assertEqual(mac, b"\xc3z\xb5j\'?\x92B\xb4\xb67&\xdf\x05\x9f\xbe")

    def test_mac_24b(self):
        mac = _cbcmac(self.data[:24], self.key)
        self.assertEqual(mac, b"p$\xe6\xaa\xd4\x16\xfc|\xf6\xc4\x8b\x04t\r\xc9o")

    def test_mac_32b(self):
        mac = _cbcmac(self.data[:32], self.key)
        self.assertEqual(mac, b"?|E|J\xdc\xbcNw\x8cD\x97<\xe8EL")
