import unittest

from scapy.layers.inet import IP

from scapy_scion.layers.int import INT
from scapy_scion.layers.scion import UDP


class TestINT(unittest.TestCase):

    def test(self):
        p = IP()/UDP(sport=51000)/INT(Flags="Discard",
            InstructionBitmap="Node ID+Hop latency+Ingress timestamp+Egress timestamp",
            Metadata=[
                {"Node ID": 1, "Hop latency": 1000, "Ingress timestamp": 1, "Egress timestamp": 2},
                [("Node ID", 3), ("Hop latency", 2000), (4, 3), (5, 4)],
                {0: 4, 2: 1000},
            ]
        )

        ip = IP(bytes(p))
        self.assertEqual(ip[UDP].dport, 51000)
        telemetry = ip[INT]
        self.assertEqual(telemetry.Flags.value, 0x4)
        self.assertEqual(telemetry.HopML, 24)
        self.assertEqual(telemetry.InstructionBitmap.value, 0xac00)
        expected = [
            [(0, 1), (2, 1000), (4, 1), (5, 2)],
            [(0, 3), (2, 2000), (4, 3), (5, 4)],
            [(0, 4), (2, 1000), (4, 0), (5, 0)]
        ]
        self.assertEqual(telemetry.Metadata, expected)
