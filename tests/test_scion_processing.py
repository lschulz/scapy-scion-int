import unittest
from pathlib import Path

from scapy.layers.inet import UDP
from scapy.packet import bind_layers
from scapy.utils import rdpcap

from layers.scion import SCION
from utils import compare_layers


class TestScionProcessing(unittest.TestCase):
    keys = {
        "ff00:0:1": "byql+EpU2czJMKtRSH8ybA==",
        "ff00:0:2": "6kWxcoeOx7QXW5Ydt9p6Ng==",
        "ff00:0:3": "lE8KhaYBJy5xHIYPdQCLMQ==",
        "ff00:0:4": "aKlN2XehHJwdhxWv/wbw0A==",
        "ff00:0:5": "DDxWeC1gVgD2uus6MewSFw==",
        "ff00:0:6": "diKD628EpzWsvOxxJiDBUg==",
        "ff00:0:7": "tAmT1zsbqdHxBmqNjSRxzA==",
    }

    @classmethod
    def setUpClass(cls):
        for i in range(31000, 31100):
            bind_layers(UDP, SCION, sport=i)
            bind_layers(UDP, SCION, dport=i)

    def test_path_processing(self):
        """Test ingress and egress processing of SCION paths including hop field validation."""

        pkts = rdpcap(str(Path(__file__).parent / "reference_pkts.pcap"))
        p = pkts[0][SCION].Path

        # Up-segment (against construction direction)
        # Hop br1-ff00_0_3-1#1 > br1-ff00_0_2-2#2 | CurrHF  = 1
        p.egress(self.keys["ff00:0:3"])
        self.assertEqual(list(compare_layers(p, pkts[1][SCION].Path)), [])

        # Hop br1-ff00_0_2-2#i > br1-ff00_0_2-1#i | InfoFields[0]/SegID= 42889
        p.ingress(self.keys["ff00:0:2"])
        self.assertEqual(list(compare_layers(p, pkts[2][SCION].Path)), [])

        # Hop br1-ff00_0_2-1#1 > br1-ff00_0_1-2#2 | CurrHF  = 2
        p.egress(self.keys["ff00:0:2"])
        self.assertEqual(list(compare_layers(p, pkts[3][SCION].Path)), [])

        # Hop br1-ff00_0_1-2#i > br1-ff00_0_1-1#i | CurrINF = 1 CurrHF  = 3 InfoFields[0]/SegID= 40275
        p.ingress(self.keys["ff00:0:1"])
        self.assertEqual(list(compare_layers(p, pkts[4][SCION].Path)), [])

        # Core-segment (against construction direction)
        # Hop br1-ff00_0_1-1#1 > br2-ff00_0_4-1#1 | CurrHF  = 4
        p.egress(self.keys["ff00:0:1"])
        self.assertEqual(list(compare_layers(p, pkts[5][SCION].Path)), [])

        # Hop br2-ff00_0_4-1#i > br2-ff00_0_4-2#i | InfoFields[1]/SegID= 22540
        p.ingress(self.keys["ff00:0:4"])
        self.assertEqual(list(compare_layers(p, pkts[6][SCION].Path)), [])

        # Hop br2-ff00_0_4-2#2 > br3-ff00_0_5-1#1 | CurrHF  = 5
        p.egress(self.keys["ff00:0:4"])
        self.assertEqual(list(compare_layers(p, pkts[7][SCION].Path)), [])

        # Hop br3-ff00_0_5-1#i > br3-ff00_0_5-2#i | CurrINF = 2 CurrHF  = 6 InfoFields[1]/SegID= 27025
        p.ingress(self.keys["ff00:0:5"])
        self.assertEqual(list(compare_layers(p, pkts[8][SCION].Path)), [])

        # Down-segment (in construction direction)
        # Hop br3-ff00_0_5-2#2 > br3-ff00_0_6-1#1 | CurrHF  = 7 InfoFields[2]/SegID= 59853
        p.egress(self.keys["ff00:0:5"])
        self.assertEqual(list(compare_layers(p, pkts[9][SCION].Path)), [])

        # Hop br3-ff00_0_6-1#i > br3-ff00_0_6-2#i |
        p.ingress(self.keys["ff00:0:6"])
        self.assertEqual(list(compare_layers(p, pkts[10][SCION].Path)), [])

        # Hop br3-ff00_0_6-2#2 > br3-ff00_0_7-1#1 | CurrHF  = 8 InfoFields[2]/SegID= 13333
        p.egress(self.keys["ff00:0:6"])
        self.assertEqual(list(compare_layers(p, pkts[11][SCION].Path)), [])

        # Hop br3-ff00_0_7-1#i > Dispatcher       |
        p.ingress(self.keys["ff00:0:7"])
        self.assertEqual(list(compare_layers(p, pkts[12][SCION].Path)), [])
