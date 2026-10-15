#!/usr/bin/env python3

import argparse
import ipaddress
import secrets
from socket import AddressFamily

from scapy.base_classes import Net
from scapy.contrib.stun import STUN, STUNFingerprint, STUNXorMappedAddress, STUNMappedAddress
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach
from scapy.libs.crc import CRC_32
from scapy.sendrecv import sr
from scapy.utils6 import Net6
from scapy.volatile import RandNum

AF_INET = AddressFamily.AF_INET
FINGERPRINT_MAGIC = 0x5354554e


def net_range(raw):
    if "-" not in raw:
        if ":" not in raw:
            return Net(raw)
        else:
            return Net6(raw)
    else:
        comps = raw.split("-")
        if len(comps) != 2:
            raise ValueError("invalid address range")
        if ":" not in comps[0]:
            return Net(net=comps[0], stop=comps[1])
        else:
            return Net6(net=comps[0], stop=comps[1])


def port_range(raw):
    ports = []
    for x in raw.split(","):
        comps = x.split("-")
        if len(comps) == 1:
            port = int(comps[0])
            if 0 < port < 65536:
                ports.append(port)
            else:
                raise ValueError("invalid port")
        elif len(comps) == 2:
            first, last = int(comps[0]), int(comps[1])
            if 0 < first < 65536 and 0 < last < 65536 and first < last:
                ports.append((first, last))
            else:
                raise ValueError("invalid port range")
        else:
            raise ValueError("invalid port range")
    return ports


def main():
    parser = argparse.ArgumentParser("stunscanner", description=
        "Scans a range of IPs and ports for possible SCION border routers by sending a STUN"
        " binding request.")
    parser.add_argument("target", type=net_range, help=
        "Target address. May be a single IP address (127.0.0.1), a subnet (127.0.0.0/24), or a"
        " range of addresses (127.0.0.1-127.0.0.10).")
    parser.add_argument("port", nargs="?", type=port_range, default=3478, help=
        "Target ports. May be a single port (3478), a port range (3478-3479) or a list of ports"
        " (3478,3479,31000-310010). If no other ports are given, the default STUN port 3478 is"
        " probed.")
    parser.add_argument("-a", "--all", action="store_true", help=
        "Print all scanned ports even if filtered or closed.")
    parser.add_argument("-s", "--sport", type=int, default=None, help=
        "Source port of request packets."
        " By default random ports above 32768, changing with every packet.")
    parser.add_argument("-t", "--timeout", type=float, default=1, help=
        "Receive timeout after the last packet has been sent.")
    parser.add_argument("-f", "--no-fingerprint", action="store_true", help=
        "Do not include the FINGERPRINT attribute in the binding request. Border routers do not"
        " normally answer such packets, but generic STUN servers do.")
    parser.add_argument("-F", "--wrong-fingerprint", action="store_true", help=
        "Include the FINGERPRINT attribute with an incorrect CRC32. Border routers do not"
        " normally answer such packets, but other STUN servers might.")

    args = parser.parse_args()

    if args.target.count > 65536:
        print("Too many IP addresses")
        return 1

    hdr = IP(dst=args.target) if args.target.family == AF_INET else IPv6(dst=args.target)
    if args.sport is not None:
        hdr = hdr / UDP(dport=args.port, sport=args.sport)
    else:
        hdr = hdr / UDP(dport=args.port, sport=RandNum(32768, 65535))

    bind_req = STUN(stun_message_type = "Binding request",
        transaction_id = secrets.randbits(96)
    )
    if not args.no_fingerprint:
        bind_req.attributes.append(STUNFingerprint())
        crc = CRC_32(bytes(bind_req)[:-8])
        if args.wrong_fingerprint:
            bind_req.attributes[-1].crc_32 = crc
        else:
            bind_req.attributes[-1].crc_32 = crc ^ FINGERPRINT_MAGIC

    pkt = hdr / bind_req
    ans, unans = sr(pkt, verbose=0, timeout=args.timeout)

    summary = {"filtered": 0, "closed": 0, "open": 0, "valid": 0}
    table = []
    for query, answer in ans:
        msg, state = interpret(query, answer)
        summary[state] += 1
        if args.all or state == "open" or state == "valid":
            ip = query[IP].dst if args.target.family == AF_INET else query[IPv6].dst
            table.append(((ipaddress.ip_address(ip), query[UDP].dport), msg))

    summary["filtered"] += len(unans)
    if args.all:
        for query in unans:
            res, _ = interpret(query, None)
            ip = query[IP].dst if args.target.family == AF_INET else query[IPv6].dst
            table.append(((ipaddress.ip_address(ip), query[UDP].dport), res))

    table.sort(key=lambda x: x[0])
    for (ip, port), res in table:
        print(f"{ip} {port}", res)
    print("Valid: {}, Open: {}, Closed: {}, Filtered: {}".format(
        summary["valid"], summary["open"], summary["closed"], summary["filtered"]
    ))


def interpret(req, resp):
    if resp is None:
        return "filtered (no response)", "filtered"
    elif resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code == 3:
        return "closed", "closed"
    elif resp.haslayer(ICMPv6DestUnreach):
        return "closed", "closed"
    elif not resp.haslayer("UDP"):
        print(f"unknown {resp.summary()}"), "open"
    else:
        try:
            reply = STUN(bytes(resp[UDP].payload))
        except Exception as e:
            return f"invalid answer ({e})", "open"

        if reply.stun_message_type != 0b1_0000_0001:
            return f"no binding success response ({reply.summary()})", "open"

        if reply.transaction_id != req.transaction_id:
            return "incorrect transaction ID", "open"

        ip, xip = None, None
        port, xport = None, None
        for attr in reply.attributes:
            if isinstance(attr, STUNMappedAddress):
                ip, port = attr.ip, attr.port
            elif isinstance(attr, STUNXorMappedAddress):
                xip, xport = attr.xip, attr.xport

        if xip is not None:
            return f"open (xip={xip}, xport={xport})", "valid"
        elif ip is not None:
            return f"open (ip={ip}, port={port})", "valid"
        else:
            return "no IP in binding response", "open"


if __name__ == "__main__":
    main()
