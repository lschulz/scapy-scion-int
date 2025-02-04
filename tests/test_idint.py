import unittest

from scapy.layers.inet import IP

from scapy_scion.layers.idint import CBCMAC, IDINT, StackEntry
from scapy_scion.layers.scion import SCION, UDP, ProtocolNumbers, SCIONPath


class TestIDINT(unittest.TestCase):

    def test_idint(self):
        keys = [
            16 * b"\x01",
            16 * b"\x02",
            16 * b"\x03"
        ]

        telemetry = IDINT(
            Flags="Discard",
            AggrMode="Off",
            Verifier="ThirdParty",
            VT="IP",
            VL=4,
            InstFlags="NodeID",
            Inst1="INGRESS_TSTAMP",
            Inst2="EGRESS_TSTAMP",
            SourcePort=10,
            VerifISD=1000,
            VerifAS="ff00:0:100",
            TelemetryStack = [
                StackEntry(Flags="Ingress", Hop=2, Mask="NodeID",
                    NodeID=3, MD1=(5).to_bytes(4, 'big'), MD2=(6).to_bytes(4, 'big')),
                StackEntry(Flags="Ingress+Egress", Hop=1, Mask="NodeID",
                    NodeID=2, MD1=(3).to_bytes(4, 'big'), MD2=(4).to_bytes(2, 'big')),
                StackEntry(Flags="Source+Egress", Hop=0, Mask="NodeID",
                    NodeID=1, MD1=(1).to_bytes(4, 'big'), MD2=(2).to_bytes(4, 'big'))
            ]
        )

        telemetry.verify(keys, update=True)
        p = IP()/UDP()/SCION(Path=SCIONPath())/telemetry/UDP()

        ip = IP(bytes(p))
        self.assertEqual(ip.layers(), [IP, UDP, SCION, IDINT, UDP])
        scion = ip[SCION]
        self.assertEqual(scion.NextHdr, ProtocolNumbers["Experiment1"])
        self.assertEqual(scion.HdrLen, 40)
        idint = scion[IDINT]
        idint.verify(keys)
        self.assertEqual(idint.Flags.value, 0x08)
        self.assertEqual(idint.VerifISD, 1000)
        self.assertEqual(idint.VerifAS, "ff00:0:100")
        self.assertEqual(idint.VerifAddr, "127.0.0.1")
        stack = idint.TelemetryStack
        self.assertEqual(len(stack), 3)
        self.assertEqual(stack[0].Hop, 2)
        self.assertEqual(stack[0].ML1, 4)
        self.assertEqual(stack[0].ML2, 4)
        self.assertEqual(stack[0].ML3, 0)
        self.assertEqual(stack[0].ML4, 0)
        self.assertEqual(int.from_bytes(stack[0].MD1, 'big'), 5)
        self.assertEqual(int.from_bytes(stack[0].MD2, 'big'), 6)
        self.assertEqual(len(stack[0].Padding), 0)
        self.assertEqual(stack[1].Hop, 1)
        self.assertEqual(stack[1].ML1, 4)
        self.assertEqual(stack[1].ML2, 2)
        self.assertEqual(stack[1].ML3, 0)
        self.assertEqual(stack[1].ML4, 0)
        self.assertEqual(int.from_bytes(stack[1].MD1, 'big'), 3)
        self.assertEqual(int.from_bytes(stack[1].MD2, 'big'), 4)
        self.assertEqual(len(stack[1].Padding), 2)
        self.assertEqual(stack[2].Hop, 0)
        self.assertEqual(stack[2].ML1, 4)
        self.assertEqual(stack[2].ML2, 4)
        self.assertEqual(stack[2].ML3, 0)
        self.assertEqual(stack[2].ML4, 0)
        self.assertEqual(int.from_bytes(stack[2].MD1, 'big'), 1)
        self.assertEqual(int.from_bytes(stack[2].MD2, 'big'), 2)
        self.assertEqual(len(stack[2].Padding), 0)


class TestCBCMAC(unittest.TestCase):

    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10'
    data = bytes((2*i-1)%256 for i in range(32))

    def test_mac_16b(self):
        mac = CBCMAC(self.data[:16], self.key)
        self.assertEqual(mac, b"\xc3z\xb5j\'?\x92B\xb4\xb67&\xdf\x05\x9f\xbe")

    def test_mac_24b(self):
        mac = CBCMAC(self.data[:24], self.key)
        self.assertEqual(mac, b"p$\xe6\xaa\xd4\x16\xfc|\xf6\xc4\x8b\x04t\r\xc9o")

    def test_mac_32b(self):
        mac = CBCMAC(self.data[:32], self.key)
        self.assertEqual(mac, b"?|E|J\xdc\xbcNw\x8cD\x97<\xe8EL")
