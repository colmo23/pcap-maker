import io
import dpkt
import pytest
from pcap_maker import pcap_utils

def test_cleanup_hex():
    assert pcap_utils.cleanup_hex("aa bb cc") == "aabbcc"
    assert pcap_utils.cleanup_hex("aa\nbb\ncc") == "aabbcc"
    assert pcap_utils.cleanup_hex("aa\r\nbb\r\ncc") == "aabbcc"
    assert pcap_utils.cleanup_hex("aa \n bb \r\n cc") == "aabbcc"
    assert pcap_utils.cleanup_hex("") == ""
    assert pcap_utils.cleanup_hex("aabbcc") == "aabbcc"

def test_get_tcp_stack_defaults():
    pkt = pcap_utils.get_tcp_stack(tcp_data=b"test_data")
    assert isinstance(pkt, dpkt.ethernet.Ethernet)
    assert pkt.data.src == b"\x0a\x0a\x0a\x0a"
    assert pkt.data.dst == b"\x0a\x0a\x0a\x10"
    assert pkt.data.data.sport == 1000
    assert pkt.data.data.dport == 80
    assert pkt.data.data.data == b"test_data"

def test_get_tcp_stack_custom_values():
    pkt = pcap_utils.get_tcp_stack(
        tcp_data=b"custom_data",
        src_ip=b"\xac\x10\x00\x01", # 172.16.0.1
        dest_ip=b"\xac\x10\x00\x02", # 172.16.0.2
        tcp_src_port=12345,
        tcp_dest_port=54321,
    )
    assert pkt.data.src == b"\xac\x10\x00\x01"
    assert pkt.data.dst == b"\xac\x10\x00\x02"
    assert pkt.data.data.sport == 12345
    assert pkt.data.data.dport == 54321
    assert pkt.data.data.data == b"custom_data"

def test_get_udp_stack_defaults():
    pkt = pcap_utils.get_udp_stack(data=b"test_data")
    assert isinstance(pkt, dpkt.ethernet.Ethernet)
    assert pkt.data.src == b"\x0a\x0a\x0a\x0a"
    assert pkt.data.dst == b"\x0a\x0a\x0a\x10"
    assert pkt.data.data.sport == 1000
    assert pkt.data.data.dport == 80
    assert pkt.data.data.data == b"test_data"

def test_get_udp_stack_custom_values():
    pkt = pcap_utils.get_udp_stack(
        data=b"custom_data",
        src_ip=b"\xac\x10\x00\x01",
        dest_ip=b"\xac\x10\x00\x02",
        src_port=12345,
        dest_port=54321,
    )
    assert pkt.data.src == b"\xac\x10\x00\x01"
    assert pkt.data.dst == b"\xac\x10\x00\x02"
    assert pkt.data.data.sport == 12345
    assert pkt.data.data.dport == 54321
    assert pkt.data.data.data == b"custom_data"

def test_get_sctp_stack_defaults():
    pkt = pcap_utils.get_sctp_stack(data=b"test_data")
    assert isinstance(pkt, dpkt.ethernet.Ethernet)
    assert pkt.data.src == b"\x0a\x0a\x0a\x0a"
    assert pkt.data.dst == b"\x0a\x0a\x0a\x10"
    sctp_pkt = pkt.data.data

def test_get_sctp_stack_custom_values():
    pkt = pcap_utils.get_sctp_stack(
        data=b"custom_data",
        src_ip=b"\xac\x10\x00\x01",
        dest_ip=b"\xac\x10\x00\x02",
        src_port=12345,
        dest_port=54321,
        protocol=42,
    )
    assert pkt.data.src == b"\xac\x10\x00\x01"
    assert pkt.data.dst == b"\xac\x10\x00\x02"
    sctp_pkt = pkt.data.data

def test_get_ip_stack_defaults():
    pkt = pcap_utils.get_ip_stack(data=b"test_data")
    assert isinstance(pkt, dpkt.ethernet.Ethernet)
    assert pkt.data.p == 99
    assert pkt.data.data == b"test_data"

def test_get_ip_stack_custom_protocol():
    pkt = pcap_utils.get_ip_stack(data=b"test_data", protocol=132)
    assert pkt.data.p == 132

def test_get_ethernet_stack():
    pkt = pcap_utils.get_ethernet_stack(data=b"test_data")
    assert isinstance(pkt, dpkt.ethernet.Ethernet)
    assert pkt.data == b"test_data"

def test_make_pcap():
    pkt = pcap_utils.get_tcp_stack(tcp_data=b"test_data")
    pcap_data = pcap_utils.make_pcap(pkt)
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(pcap_data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert eth.data.data.data == b"test_data"
