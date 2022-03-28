import signal
import subprocess
from typing import List, Optional, Tuple, Union

import scapy
from scapy.sendrecv import sniff

from .layers.scion import SCION
from .layers.scmp import SCMP


class PingError(Exception):
    def __init__(self, returncode: int, output: Optional[str] = None):
        self.returncode = returncode
        self.output = output

    def __str__(self):
        s = f"Ping failed with error {self.returncode}"
        return f"{s}:\n{self.output}" if self.output else s


def capture_path(scion: str, src_br: str, sciond: str, dest: str, timeout: Optional[int] = 1,
    extra_args: List[str] = [], capture_output: bool = False) -> Union[SCION, Tuple[SCION, str]]:
    """Ping an AS and capture to echo request to extract the path from it.
    :param scion: "scion" command to use for the ping.
    :param src_br: Internal interface of a border router in the source AS.
                   Example: "127.0.0.33:31010"
    :param sciond: Address of sciond in the source AS.
                   Example: "127.0.0.35:30255"
    :param dest: Destination host in the format expected by "scion ping".
                 Example: "3-ff00:0:7,127.0.0.1"
    :param timeout: How long to wait before giving up if no packet is captured, e.g., because the
                    ping failed. The value is in seconds. None disables the timeout.
    :param extra_args: Additional command line arguments passed to 'scion ping'.
    :param capture_output: Capture the output of the 'scion ping' command and return it. If False,
                           the command's output will be written to stdout and stderr as usual.
    :returns: Captured SCION header with payload removed. If capture_output was True, a pair of the
              captures SCION header and the output of the ping command.
    :raises: PingError if the 'scion ping' command failed.
    """
    # Capture an echo request
    ping = None
    def ping_cb():
        nonlocal ping
        args = {}
        if capture_output:
            args = {'stdout': subprocess.PIPE, 'stderr': subprocess.STDOUT, 'encoding': "utf-8"}
        ping = subprocess.Popen([scion, "ping", "--sciond", sciond, dest] + extra_args, **args)

    br = src_br.split(":")
    cap = sniff(iface="lo", count=1, timeout=timeout,
        filter=f"dst {br[0]} and port {br[1]}",
        lfilter=lambda pkt: pkt.haslayer(SCMP) and pkt[SCMP].Type==128,
        started_callback=ping_cb)

    ping.send_signal(signal.SIGINT)
    if ping.wait():
        raise PingError(ping.returncode, ping.stdout.read() if ping.stdout else None)

    # Extract SCION header
    p = cap[0][SCION]
    p.remove_payload()
    del p.NextHdr
    del p.HdrLen
    del p.PayloadLen

    if capture_output:
        return (p, ping.stdout.read() if ping.stdout else None)
    else:
        return p


def compare_layers(layer1, layer2):
    """Compare the fields of two scapy layers/headers of the same type.

    Differences are returned as tuples of field name, value in `layer1` and value in `layer2`.
    Packet fields and PacketListFields are compared recursively.
    """
    for desc in layer1.fields_desc:
        a = getattr(layer1, desc.name)
        b = getattr(layer2, desc.name)
        if issubclass(type(a), scapy.packet.Packet):
            yield from compare_layers(a, b)
        elif isinstance(desc, scapy.fields.PacketListField):
            for i, (sublayer1, sublayer2) in enumerate(zip(a, b)):
                for diff in compare_layers(sublayer1, sublayer2):
                    yield ("{}[{}]/{}".format(desc.name, i, diff[0]), diff[1], diff[2])
        else:
            if a != b:
                yield (desc.name, a, b)
