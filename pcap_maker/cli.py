#!/usr/bin/env python3

"cli"

import argparse
import binascii
import sys
from datetime import date

from . import pcap_utils


def read_hex_input(args):
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            hex_string = fh.read()
    elif args.hex:
        hex_string = args.hex
    else:
        hex_string = sys.stdin.read()
    hex_string = pcap_utils.cleanup_hex(hex_string)
    return binascii.a2b_hex(hex_string)


def default_output_name(protocol):
    today = date.today().strftime("%Y%m%d")
    return f"{protocol}-{today}.pcap"


def do_tcp_pcap(args):
    tcp_data = read_hex_input(args)
    try:
        pkt = pcap_utils.get_tcp_stack(
            tcp_data=tcp_data, tcp_src_port=args.sport, tcp_dest_port=args.dport
        )
        return pcap_utils.make_pcap(pkt)
    except pcap_utils.PayloadTooLargeError:
        # Too big for one packet - split across multiple TCP segments so
        # Wireshark reassembles the stream instead of erroring out.
        pkts = pcap_utils.get_tcp_stream_stack(
            tcp_data=tcp_data, tcp_src_port=args.sport, tcp_dest_port=args.dport
        )
        return pcap_utils.make_pcap_multi(pkts)


def do_udp_pcap(args):
    data = read_hex_input(args)
    pkt = pcap_utils.get_udp_stack(data=data, src_port=args.sport, dest_port=args.dport)
    return pcap_utils.make_pcap(pkt)


def do_sctp_pcap(args):
    data = read_hex_input(args)
    pkt = pcap_utils.get_sctp_stack(
        data=data, src_port=args.sport, dest_port=args.dport, protocol=args.protocol
    )
    return pcap_utils.make_pcap(pkt)


def do_sccp_pcap(args):
    data = read_hex_input(args)
    pkt = pcap_utils.get_sccp_stack(data=data)
    return pcap_utils.make_pcap(pkt)


def do_tcap_pcap(args):
    data = read_hex_input(args)
    pkt = pcap_utils.get_tcap_stack(data=data)
    return pcap_utils.make_pcap(pkt)


def do_ip_pcap(args):
    data = read_hex_input(args)
    pkt = pcap_utils.get_ip_stack(data=data, protocol=args.protocol)
    return pcap_utils.make_pcap(pkt)


def do_ethernet_pcap(args):
    data = read_hex_input(args)
    pkt = pcap_utils.get_ethernet_stack(data=data)
    return pcap_utils.make_pcap(pkt)


def do_full_pcap(args):
    data = read_hex_input(args)
    return pcap_utils.make_pcap(data, linktype=args.linktype)


PROTOCOL_HANDLERS = {
    "tcp": do_tcp_pcap,
    "udp": do_udp_pcap,
    "sctp": do_sctp_pcap,
    "sccp": do_sccp_pcap,
    "tcap": do_tcap_pcap,
    "ip": do_ip_pcap,
    "ethernet": do_ethernet_pcap,
    "full": do_full_pcap,
}


def add_input_args(sub):
    group = sub.add_mutually_exclusive_group()
    group.add_argument("--hex", help="Hex string of the packet payload")
    group.add_argument("--file", help="Path to a file containing the hex dump")
    sub.add_argument("-o", "--output", help="Output pcap file path")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pcap-maker",
        description="Generate a pcap file from a hex packet dump. "
        "Hex input is read from --hex, --file, or stdin if neither is given.",
    )
    subparsers = parser.add_subparsers(dest="protocol", required=True)

    tcp = subparsers.add_parser("tcp", help="TCP / IP / Ethernet")
    add_input_args(tcp)
    tcp.add_argument("--sport", type=int, default=1000)
    tcp.add_argument("--dport", type=int, default=80)

    udp = subparsers.add_parser("udp", help="UDP / IP / Ethernet")
    add_input_args(udp)
    udp.add_argument("--sport", type=int, default=1000)
    udp.add_argument("--dport", type=int, default=80)

    sctp = subparsers.add_parser("sctp", help="SCTP / IP / Ethernet")
    add_input_args(sctp)
    sctp.add_argument("--sport", type=int, default=2905)
    sctp.add_argument("--dport", type=int, default=2905)
    sctp.add_argument(
        "--protocol", type=int, default=3, help="Payload protocol id (3=M3UA, 2=M2UA)"
    )

    sccp = subparsers.add_parser("sccp", help="SCCP / M3UA / SCTP / IP / Ethernet")
    add_input_args(sccp)

    tcap = subparsers.add_parser("tcap", help="TCAP / M3UA / SCTP / IP / Ethernet")
    add_input_args(tcap)

    ip_parser = subparsers.add_parser(
        "ip", help="IP / Ethernet (custom protocol number)"
    )
    add_input_args(ip_parser)
    ip_parser.add_argument("--protocol", type=int, default=99)

    ethernet = subparsers.add_parser("ethernet", help="Ethernet (raw)")
    add_input_args(ethernet)

    full = subparsers.add_parser(
        "full", help="User-specified linktype with raw payload"
    )
    add_input_args(full)
    full.add_argument("--linktype", type=int, default=1)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = PROTOCOL_HANDLERS[args.protocol]
    try:
        pcap_bytes = bytes(handler(args))
    except pcap_utils.PayloadTooLargeError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except (binascii.Error, ValueError) as err:
        print(f"Error: invalid hex input: {err}", file=sys.stderr)
        return 1

    output_path = args.output or default_output_name(args.protocol)
    with open(output_path, "wb") as fh:
        fh.write(pcap_bytes)
    print(f"Wrote {len(pcap_bytes)} bytes to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
