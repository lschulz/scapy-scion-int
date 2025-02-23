import unittest

from scapy.layers.inet import IP

from scapy_scion.layers.int import INT
from scapy_scion.layers.scion import UDP


class TestINT(unittest.TestCase):

    def test(self):
        p = IP()/UDP(sport=51000)/INT(flags="discard",
            instr_bitmap="Node ID+Hop latency+Ingress timestamp+Egress timestamp",
            metadata=[
                {"Node ID": 1, "Hop latency": 1000, "Ingress timestamp": 1, "Egress timestamp": 2},
                [("Node ID", 3), ("Hop latency", 2000), (4, 3), (5, 4)],
                {0: 4, 2: 1000},
            ]
        )

        ip = IP(bytes(p))
        self.assertEqual(ip[UDP].dport, 51000)
        telemetry = ip[INT]
        self.assertEqual(telemetry.flags.value, 0x4)
        self.assertEqual(telemetry.hop_ml, 24 // 4)
        self.assertEqual(telemetry.instr_bitmap.value, 0xac00)
        expected = [
            [(0, 1), (2, 1000), (4, 1), (5, 2)],
            [(0, 3), (2, 2000), (4, 3), (5, 4)],
            [(0, 4), (2, 1000), (4, 0), (5, 0)]
        ]
        self.assertEqual(telemetry.metadata, expected)
