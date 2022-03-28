#!/usr/bin/env python3

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Mapping

import scapy.main
from scapy.fields import IntField
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet, bind_layers
from scapy.sendrecv import AsyncSniffer

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from scapy_scion.layers.scion import SCION
from scapy_scion.utils import capture_path, compare_layers

TEST_PORT = 6500

class PROBEHDR(Packet):
    name = "Probe"
    fields_desc = [
        IntField("seq", default=0)
    ]

bind_layers(UDP, PROBEHDR, dport=TEST_PORT)


def get_br_addresses(gen: Path) -> Dict[str, Any]:
    """Extract the BR sections from the 'topology.json' files of every as in the "gen folder" and
    merge them in a single directory.
    :param gen: path to the "gen folder"
    """
    brs = {}
    with os.scandir(gen) as iter:
        for dir in iter:
            if dir.name.startswith("AS"):
                with open(Path(dir.path) / "topology.json") as f:
                    topo = json.load(f)
                    brs.update(topo["border_routers"])
    return brs


def get_sciond_addresses(gen: Path) -> Dict[str, Any]:
    """Parse the 'scion_addresses.json' file from the "gen folder".
    :param gen: path to the "gen folder"
    """
    with open(gen / "sciond_addresses.json") as f:
        return json.load(f)


def bind_scion_layer(brs: Mapping[str, Any]):
    """Tell Scapy to interpret all UDP packets from an to the border router interfaces as containing
    SCION packets.
    :param brs: BR information parsed by get_br_addresses()
    """
    for br in brs.values():
        _, port = br["internal_addr"].split(":")
        bind_layers(UDP, SCION, sport=int(port))
        bind_layers(UDP, SCION, dport=int(port))
        for iface in br["interfaces"].values():
            _, port = iface["underlay"]["public"].split(":")
            bind_layers(UDP, SCION, sport=int(port))
            bind_layers(UDP, SCION, dport=int(port))


class PathSniffer():
    """Wrapper for Scapy's AsyncSniffer. Captures out probe packets as the leave/enter BRs and
    prints the differences from hop to hop.
    """
    def __init__(self, brs, num_addr=False, **kwargs):
        self.sniffer = AsyncSniffer(iface="lo", store=False,
        lfilter=self._filter, prn=lambda pkt: self._prn(pkt),
        **kwargs)

        self.num_addr = num_addr
        self.packets = []

        # Dictionary for (IP, port) -> BR lookup
        if not num_addr:
            self.addr_table = {}
            for br_name, br in brs.items():
                ip, port= br["internal_addr"].split(":")
                self.addr_table[(ip, int(port))] = f"{br_name}#i"
                for iface_name, iface in br["interfaces"].items():
                    ip, port = iface["underlay"]["public"].split(":")
                    self.addr_table[(ip, int(port))] = f"{br_name}#{iface_name}"

    @staticmethod
    def _filter(pkt):
        if pkt.haslayer(SCION) and pkt[SCION].haslayer(UDP):
            udp = pkt.getlayer(UDP, 2)
            return udp.haslayer(PROBEHDR)
        return False

    def _prn(self, pkt):
        ip = pkt[IP]
        udp = pkt.getlayer(UDP, 1)
        seq = pkt[PROBEHDR].seq
        last_packet = self.packets[-1] if len(self.packets) else None

        # Skip packets that have already been printed. Packets on the loopback interface are
        # captured twice, on send and on receive.
        if last_packet and last_packet[IP] == ip and last_packet[PROBEHDR].seq == seq:
            return

        if self.num_addr:
            print(f"Hop {ip.src:>11}:{udp.sport} > {ip.dst:>11}:{udp.dport} |", end="")
        else:
            src = self.addr_table.get((ip.src, udp.sport), "Source")
            dst = self.addr_table.get((ip.dst, udp.dport), "Dispatcher")
            print(f"Hop {src:<16} > {dst:<16} |", end="")

        if last_packet and last_packet[PROBEHDR].seq == seq:
            for diff in compare_layers(last_packet[SCION], pkt[SCION]):
                print(" {0:<8}= {2}".format(*diff), end="")

        print()
        self.packets.append(pkt)

    def start(self):
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()


def send_probes(br: str, path: SCION, count: int):
    """Send probe packets to a border router.
    :param br: Internal interface of the border router the probe will initially be sent to.
    :param path: SCION header with a valid path.
    :param count: Number of probes to send.
    """
    ip, port = br.split(":")
    port = int(port)
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        p = path / UDP(dport=TEST_PORT, sport=TEST_PORT) / PROBEHDR(seq=i)
        print(f"Sending probe to {ip}:{port}: ", p.summary())
        skt.sendto(bytes(p), (ip, port))


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Print the changes occurring in the SCION packet header while a packet"
            " traverses border routers on its path. Only works with local topologies where every"
            " packet passes through the loopback interface.")
    parser.add_argument("-s", "--scion", type=Path, required=True,
        help="Path to the root of the SCION source tree")
    parser.add_argument("--br", default="br1-ff00_0_3-1", help="BR in the source AS")
    parser.add_argument("--dst", default="3-ff00:0:7", help="Destination AS")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of probes")
    parser.add_argument("-n", "--numerical", action="store_true", help="Show numerical addresses")
    parser.add_argument("-p", "--select-path", action="store_true",
        help="Pick a path interactively")
    parser.add_argument("-i", "--interactive", action="store_true",
        help="Start an interactive shell to inspect the probes in more detail")
    args = parser.parse_args()

    # Get addresses of local SCION services
    brs = get_br_addresses(args.scion / "gen")
    scionds = get_sciond_addresses(args.scion / "gen")

    # Interpret packets from/to BRs as SCION
    bind_scion_layer(brs)

    # Prepare source and destination addresses
    src_br = brs[args.br]["internal_addr"]
    m = re.match(r"br(\d+-[^-]*)-.*", args.br)
    src_as = m[1].replace("_", ":")
    sciond = scionds[src_as] + ":30255"
    dest = args.dst + ",127.0.0.1"

    # Capture a valid SCION header from a call to "scion ping"
    print("### Ping destination AS", flush=True) # Flush stream so that output from ping does not
                                                 # get mixed in
    ping_args = {'extra_args': ["-i"], 'timeout': None} if args.select_path else {}
    path = capture_path(str(args.scion / "bin/scion"), src_br, sciond, dest, **ping_args)

    # Capture a probe packet after passing through every border router
    print("### Trace probe packet")
    started_event = threading.Event()
    sniffer = PathSniffer(brs, args.numerical, started_callback=lambda: started_event.set())
    sniffer.start()
    started_event.wait()
    send_probes(src_br, path, args.count)
    time.sleep(0.250)
    sniffer.stop()

    if args.interactive:
        scapy.main.interact(mydict={'path': path, 'pkts': sniffer.packets, **globals()}, argv=[])


if __name__ == "__main__":
    main()
