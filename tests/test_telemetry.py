import unittest

from layers.scion import (SCION, HopByHopExt, PadNOption, ProtocolNumbers,
                          SCIONPath)
from layers.telemetry import Report, TelemetryOption


class TestSCIONTelemetry(unittest.TestCase):

    def test_telemetry(self):
        telemetry_opt = TelemetryOption(
            Flags="Discard",
            AggregationMode="Off",
            RemainingHopCount=10,
            FixedInst="NodeID+InTime+EgTime",
            VarInstPlane=1,
            VarInst={"INT_EgTx"},
            Hops = [
                Report(Flags="Ingress+Egress", Hop=2, Metadata={
                    "NodeID": 1, "InTime": 9, "EgTime": 10
                }),
                Report(Flags="Egress", Hop=1, Metadata={
                    "NodeID": 2, "InTime": 7, "EgTime": 8
                }),
                Report(Flags=0, Hop=1, Metadata={
                    "NodeID": 15, "InTime": 5, "EgTime": 6, "INT_EgTx": 500
                }),
                Report(Flags="Ingress", Hop=1, Metadata={
                    "NodeID": 10, "InTime": 3, "EgTime": 4, "INT_EgTx": 1000
                }),
                Report(Flags="Ingress+Egress", Hop=0, Metadata={
                    "NodeID": 0, "InTime": 1, "EgTime": 2
                })
            ]
        )

        p = SCION(Path=SCIONPath())
        p = p/HopByHopExt(Options=[PadNOption(), telemetry_opt])

        scion = SCION(bytes(p))
        self.assertEqual(p.layers(), [SCION, HopByHopExt])
        self.assertEqual(scion.NextHdr, ProtocolNumbers["HopByHopExt"])
        self.assertEqual(scion.HdrLen, 40)
        hbh = scion[HopByHopExt]
        self.assertEqual(hbh.ExtLen, 40)
        telemetry = hbh.Options[1]
        self.assertEqual(telemetry.OptDataLen, 154)
        self.assertEqual(telemetry.Flags.value, 0x10)
        self.assertEqual(telemetry.VarInstPlane, 1)
        self.assertEqual(telemetry.FixedInst, 0xb0)
        self.assertEqual(telemetry.VarInst, {"INT_EgTx"})
        hops = telemetry.Hops
        self.assertEqual(len(hops), 5)
        self.assertEqual(hops[0].Hop, 2)
        self.assertEqual(hops[0].MetadataMask, 0x00b0)
        self.assertEqual(len(hops[0].Metadata.data), 3)
        self.assertEqual(hops[1].Hop, 1)
        self.assertEqual(hops[1].MetadataMask, 0x00b0)
        self.assertEqual(len(hops[1].Metadata.data), 3)
        self.assertEqual(hops[2].Hop, 1)
        self.assertEqual(hops[2].MetadataMask, 0x01b0)
        self.assertEqual(len(hops[2].Metadata.data), 4)
        self.assertEqual(hops[3].Hop, 1)
        self.assertEqual(hops[3].MetadataMask, 0x01b0)
        self.assertEqual(len(hops[3].Metadata.data), 4)
        self.assertEqual(hops[4].Hop, 0)
        self.assertEqual(hops[4].MetadataMask, 0x00b0)
        self.assertEqual(len(hops[4].Metadata.data), 3)
