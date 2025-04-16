import unittest
from pathlib import Path

from scapy.utils import rdpcap

from scapy_scion.layers.scion import SCION, HopField, InfoField, SCIONPath
from scapy_scion.utils import compare_layers


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
    path_keys = [
        # Up segment
        keys["ff00:0:3"], keys["ff00:0:2"], keys["ff00:0:1"],
        # Core segment
        keys["ff00:0:1"], keys["ff00:0:4"], keys["ff00:0:5"],
        # Down segment
        keys["ff00:0:5"], keys["ff00:0:6"], keys["ff00:0:7"],
    ]

    def test_path_processing(self):
        """Test ingress and egress processing of SCION paths including hop field validation"""

        pkts = rdpcap(str(Path(__file__).parent / "reference_pkts.pcap"))
        p = pkts[0][SCION].path.copy()
        p.init_path(self.path_keys, seeds=[b"\x9d\x53", b"\x69\x91", b"\x40\x73"])
        self.assertEqual(list(compare_layers(p, pkts[0][SCION].path)), [])

        # Up-segment (against construction direction)
        # Hop br1-ff00_0_3-1#1 > br1-ff00_0_2-2#2 | CurrHF  = 1
        p.egress(self.keys["ff00:0:3"])
        self.assertEqual(list(compare_layers(p, pkts[1][SCION].path)), [])

        # Hop br1-ff00_0_2-2#i > br1-ff00_0_2-1#i | InfoFields[0]/SegID= 42889
        p.ingress(self.keys["ff00:0:2"])
        self.assertEqual(list(compare_layers(p, pkts[2][SCION].path)), [])

        # Hop br1-ff00_0_2-1#1 > br1-ff00_0_1-2#2 | CurrHF  = 2
        p.egress(self.keys["ff00:0:2"])
        self.assertEqual(list(compare_layers(p, pkts[3][SCION].path)), [])

        # Hop br1-ff00_0_1-2#i > br1-ff00_0_1-1#i | CurrINF = 1 CurrHF  = 3 InfoFields[0]/SegID= 40275
        p.ingress(self.keys["ff00:0:1"])
        self.assertEqual(list(compare_layers(p, pkts[4][SCION].path)), [])

        # Core-segment (against construction direction)
        # Hop br1-ff00_0_1-1#1 > br2-ff00_0_4-1#1 | CurrHF  = 4
        p.egress(self.keys["ff00:0:1"])
        self.assertEqual(list(compare_layers(p, pkts[5][SCION].path)), [])

        # Hop br2-ff00_0_4-1#i > br2-ff00_0_4-2#i | InfoFields[1]/SegID= 22540
        p.ingress(self.keys["ff00:0:4"])
        self.assertEqual(list(compare_layers(p, pkts[6][SCION].path)), [])

        # Hop br2-ff00_0_4-2#2 > br3-ff00_0_5-1#1 | CurrHF  = 5
        p.egress(self.keys["ff00:0:4"])
        self.assertEqual(list(compare_layers(p, pkts[7][SCION].path)), [])

        # Hop br3-ff00_0_5-1#i > br3-ff00_0_5-2#i | CurrINF = 2 CurrHF  = 6 InfoFields[1]/SegID= 27025
        p.ingress(self.keys["ff00:0:5"])
        self.assertEqual(list(compare_layers(p, pkts[8][SCION].path)), [])

        # Down-segment (in construction direction)
        # Hop br3-ff00_0_5-2#2 > br3-ff00_0_6-1#1 | CurrHF  = 7 InfoFields[2]/SegID= 59853
        p.egress(self.keys["ff00:0:5"])
        self.assertEqual(list(compare_layers(p, pkts[9][SCION].path)), [])

        # Hop br3-ff00_0_6-1#i > br3-ff00_0_6-2#i |
        p.ingress(self.keys["ff00:0:6"])
        self.assertEqual(list(compare_layers(p, pkts[10][SCION].path)), [])

        # Hop br3-ff00_0_6-2#2 > br3-ff00_0_7-1#1 | CurrHF  = 8 InfoFields[2]/SegID= 13333
        p.egress(self.keys["ff00:0:6"])
        self.assertEqual(list(compare_layers(p, pkts[11][SCION].path)), [])

        # Hop br3-ff00_0_7-1#i > Dispatcher       |
        p.ingress(self.keys["ff00:0:7"])
        self.assertEqual(list(compare_layers(p, pkts[12][SCION].path)), [])

    def test_path_construction(self):
        """Test initialization of MAC and SegID fields"""
        p = SCIONPath(
            seg0_len=3, seg1_len=3, seg2_len=3,
            info_fields=[
                InfoField(),
                InfoField(),
                InfoField(flags="C"),
            ],
            hop_fields=[
                HopField(cons_ingress=1, cons_egress=0),
                HopField(cons_ingress=1, cons_egress=2),
                HopField(cons_ingress=0, cons_egress=2),
                HopField(cons_ingress=1, cons_egress=0),
                HopField(cons_ingress=2, cons_egress=1),
                HopField(cons_ingress=0, cons_egress=1),
                HopField(cons_ingress=0, cons_egress=2),
                HopField(cons_ingress=1, cons_egress=2),
                HopField(cons_ingress=1, cons_egress=0),
            ]
        )

        p.init_path(self.path_keys)

        # Check MACs
        # Up segment
        p.egress(self.keys["ff00:0:3"])
        p.ingress(self.keys["ff00:0:2"])
        p.egress(self.keys["ff00:0:2"])
        p.ingress(self.keys["ff00:0:1"])
        # Core segment
        p.egress(self.keys["ff00:0:1"])
        p.ingress(self.keys["ff00:0:4"])
        p.egress(self.keys["ff00:0:4"])
        p.ingress(self.keys["ff00:0:5"])
        # Down segment
        p.egress(self.keys["ff00:0:5"])
        p.ingress(self.keys["ff00:0:6"])
        p.egress(self.keys["ff00:0:6"])
        p.ingress(self.keys["ff00:0:7"])

    def test_mac_key_derivation(self):
        """Test the AS secret key derivation helper"""
        self.assertEqual(
            SCIONPath.derive_hf_mac_key(b"IAOYbTs/CobLFV3T3jt6lQ=="),
            b"xEg7WN/vMCn+ccb3P7O/5A=="
        )


class TestScionProcessingPeering(unittest.TestCase):
    keys = {
        "ff00:0:2": SCIONPath.derive_hf_mac_key(b"EYDAaz+kjU3oRjIbpKb9KA=="),
        "ff00:0:3": SCIONPath.derive_hf_mac_key(b"KaOWYQzTRKxth6snjkpC6w=="),
        "ff00:0:4": SCIONPath.derive_hf_mac_key(b"PS9v/wDN+MtPxUMETmSD0Q=="),
        "ff00:0:6": SCIONPath.derive_hf_mac_key(b"sqjs0d5RR4WZ9xVYPJQe3w=="),
        "ff00:0:7": SCIONPath.derive_hf_mac_key(b"h5uncRJpiDD2fbD849HG1g=="),
        "ff00:0:8": SCIONPath.derive_hf_mac_key(b"LozRH4FpmlEj4JJpo4IQLg=="),
    }
    path_keys = [
        # up
        keys["ff00:0:4"], keys["ff00:0:3"], keys["ff00:0:2"],
        # down
        keys["ff00:0:6"], keys["ff00:0:7"], keys["ff00:0:8"],
    ]

    def test_peering_path_processing(self):
        """Test processing of a SCION path containing a peering link"""

        pkts = rdpcap(str(Path(__file__).parent / "reference_pkts_peering.pcap"))
        p = pkts[0][SCION].path.copy()

        # Up Segment
        # Hop br1-ff00_0_4-1#1 > br1-ff00_0_3-2#2 | curr_hf = 1
        p.egress(self.keys["ff00:0:4"])
        self.assertEqual(list(compare_layers(p, pkts[1][SCION].path)), [])

        # Hop br1-ff00_0_3-2#i > br1-ff00_0_3-1#i | info_fields[0]/segid= 31823
        p.ingress(self.keys["ff00:0:3"])
        self.assertEqual(list(compare_layers(p, pkts[2][SCION].path)), [])

        # Hop br1-ff00_0_3-1#1 > br1-ff00_0_2-2#2 | curr_hf = 2
        p.egress(self.keys["ff00:0:3"])
        self.assertEqual(list(compare_layers(p, pkts[3][SCION].path)), [])

        # Special peering rules
        # Hop br1-ff00_0_2-2#i > br1-ff00_0_2-3#i |
        p.ingress(self.keys["ff00:0:2"])
        self.assertEqual(list(compare_layers(p, pkts[4][SCION].path)), [])

        # Hop br1-ff00_0_2-3#3 > br2-ff00_0_6-3#3 | curr_inf= 1 curr_hf = 3
        p.egress(self.keys["ff00:0:2"])
        self.assertEqual(list(compare_layers(p, pkts[5][SCION].path)), [])

        # Hop br2-ff00_0_6-3#i > br2-ff00_0_6-2#i |
        p.ingress(self.keys["ff00:0:6"])
        self.assertEqual(list(compare_layers(p, pkts[6][SCION].path)), [])

        # Hop br2-ff00_0_6-2#2 > br2-ff00_0_7-1#1 | curr_hf = 4
        p.egress(self.keys["ff00:0:6"])
        self.assertEqual(list(compare_layers(p, pkts[7][SCION].path)), [])

        # Down Segment
        # Hop br2-ff00_0_7-1#i > br2-ff00_0_7-2#i |
        p.ingress(self.keys["ff00:0:7"])
        self.assertEqual(list(compare_layers(p, pkts[8][SCION].path)), [])

        # Hop br2-ff00_0_7-2#2 > br2-ff00_0_8-1#1 | curr_hf = 5 info_fields[1]/segid= 59436
        p.egress(self.keys["ff00:0:7"])
        self.assertEqual(list(compare_layers(p, pkts[9][SCION].path)), [])

        # Hop br2-ff00_0_8-1#i > Destination      |
        p.ingress(self.keys["ff00:0:8"])
        self.assertEqual(list(compare_layers(p, pkts[10][SCION].path)), [])
