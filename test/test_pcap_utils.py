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

def test_get_sctp_stack_chunk_padding():
    # Chunk value = 12 fixed fields + user data; must be padded to 4-byte boundary.
    # 1-byte payload: chunk value = 13 bytes → 3 bytes of padding required.
    pkt = pcap_utils.get_sctp_stack(data=b"A")
    sctp_raw = pkt.data.data
    sctp_pkt = dpkt.sctp.SCTP(sctp_raw)
    chunk = sctp_pkt.chunks[0]
    # Length field = 4 (header) + 13 (value) = 17; must NOT include padding.
    assert chunk.len == 17
    # Serialised chunk must be padded to a multiple of 4 bytes.
    assert len(bytes(chunk)) % 4 == 0
    # Padding bytes must be zero.
    assert bytes(chunk)[-3:] == b"\x00\x00\x00"

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

def test_get_tcp_stack_oversized_raises():
    with pytest.raises(pcap_utils.PayloadTooLargeError):
        pcap_utils.get_tcp_stack(tcp_data=b"A" * 70000)

def test_get_udp_stack_oversized_raises():
    # UDP: 20-byte IP + 8-byte UDP header + data; limit is 65535
    # 65508 bytes of data pushes ip_total_len to 65536
    with pytest.raises(pcap_utils.PayloadTooLargeError) as exc_info:
        pcap_utils.get_udp_stack(data=b"A" * 65508)
    assert "65535" in str(exc_info.value)
    assert "Payload too large" in str(exc_info.value)

def test_get_sctp_stack_oversized_raises():
    # 20 IP + 12 SCTP base + 4 chunk header + 12 chunk data fields = 48 bytes overhead
    # 65488 bytes of payload pushes ip_total_len to 65536, exceeding the limit
    with pytest.raises(pcap_utils.PayloadTooLargeError) as exc_info:
        pcap_utils.get_sctp_stack(data=b"A" * 65488)
    assert "65535" in str(exc_info.value)
    assert "Payload too large" in str(exc_info.value)

def test_get_tcp_stream_stack_splits_and_preserves_data():
    data = b"A" * 4000
    packets = pcap_utils.get_tcp_stream_stack(tcp_data=data, mss=1460)
    assert len(packets) == 3
    reassembled = b"".join(pkt.data.data.data for pkt in packets)
    assert reassembled == data
    seqs = [pkt.data.data.seq for pkt in packets]
    assert seqs == [0, 1460, 2920]

def test_get_tcp_stream_stack_pcap_roundtrip():
    data = b"A" * 70000
    packets = pcap_utils.get_tcp_stream_stack(tcp_data=data)
    pcap_data = pcap_utils.make_pcap_multi(packets)
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(pcap_data))
    reassembled = b"".join(
        dpkt.ethernet.Ethernet(buf).data.data.data for ts, buf in pcap_reader
    )
    assert reassembled == data
