import binascii
import dpkt
import io
import struct


def cleanup_hex(hex_string):
    hex_string = "".join(hex_string.split("\r\n"))
    hex_string = "".join(hex_string.split("\n"))
    hex_string = "".join(hex_string.split(" "))
    return hex_string


def get_tcp_stack(
    tcp_data,
    src_ip=b"\x0a\x0a\x0a\x0a",
    dest_ip=b"\x0a\x0a\x0a\x10",
    tcp_src_port=1000,
    tcp_dest_port=80,
):
    tcp_part = dpkt.tcp.TCP(sport=tcp_src_port, dport=tcp_dest_port, data=tcp_data)
    ip_part = dpkt.ip.IP(
        src=src_ip,
        dst=dest_ip,
        p=dpkt.ip.IP_PROTO_TCP,
        len=20 + len(str(tcp_part)),
        data=tcp_part,
    )
    eth_part = dpkt.ethernet.Ethernet(
        #                                     src = eth_pkt.dst,
        #                                     dst = eth_pkt.src,
        data=ip_part
    )
    return eth_part


def get_udp_stack(
    data,
    src_ip=b"\x0a\x0a\x0a\x0a",
    dest_ip=b"\x0a\x0a\x0a\x10",
    src_port=1000,
    dest_port=80,
):
    l3_part = dpkt.udp.UDP(
        sport=src_port, dport=dest_port, ulen=8 + len(data), data=data
    )
    ip_part = dpkt.ip.IP(
        src=src_ip,
        dst=dest_ip,
        p=dpkt.ip.IP_PROTO_UDP,
        len=20 + len(str(l3_part)),
        data=l3_part,
    )
    eth_part = dpkt.ethernet.Ethernet(
        #                                     src = eth_pkt.dst,
        #                                     dst = eth_pkt.src,
        data=ip_part
    )
    return eth_part


def get_sctp_stack(
    data,
    src_ip=b"\x0a\x0a\x0a\x0a",
    dest_ip=b"\x0a\x0a\x0a\x10",
    src_port=2905,
    dest_port=2905,
    protocol=3,
):
    data_chunk = dpkt.sctp.Chunk(type=dpkt.sctp.DATA)
    chunk_tsn = b"\x00\x10\x20\x30"
    chunk_stream_id = b"\x00\x80"
    chunk_protocol_id = struct.pack("!i", protocol)
    chunk_seq = b"\x00\x2a"
    data_chunk.data = (
        chunk_tsn + chunk_stream_id + chunk_seq + chunk_protocol_id + bytes(data)
    )
    padding_len = 4 - (len(data_chunk.data) % 4)
    # data_chunk.padding = b'\x00' * padding_len
    data_chunk.padding = b""
    data_chunk.len = len(data_chunk.data) + padding_len
    data_chunk.flags = 0x03
    l3_part = dpkt.sctp.SCTP(sport=src_port, dport=dest_port)
    l3_part.chunks = [data_chunk]
    l3_part_bytes = bytes(l3_part)
    ip_part = dpkt.ip.IP(
        src=src_ip,
        dst=dest_ip,
        p=dpkt.ip.IP_PROTO_SCTP,
        len=20 + len(l3_part_bytes),
        data=l3_part_bytes,
    )
    eth_part = dpkt.ethernet.Ethernet(data=ip_part)
    return eth_part


def get_tcap_stack(data):
    # hex: "010001010000009c00060008000000010210008900000065000015b0030200070900030e190b12080a12041808390100000b12080a12045383160002005b6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619000000"
    padding_len = (len(data) + 2) % 4
    if padding_len != 0:
        padding_len = 4 - padding_len
    padding = b"\x00" * padding_len
    parameter_length = 46 + len(data)
    parameter_length_field = "%04x" % (parameter_length)
    m3ua_length = parameter_length + 16 + padding_len
    m3ua_length_field = "%08x" % (m3ua_length)
    sccp_parameter_3_length_field = "%02x" % len(data)
    m3ua_sccp_data_hex = f"01000101{m3ua_length_field}00060008000000010210{parameter_length_field}00000065000015b0030200070900030e190b12080a12041808390100000b12080a1204538316000200{sccp_parameter_3_length_field}"
    sctp_data = binascii.a2b_hex(m3ua_sccp_data_hex) + bytes(data) + padding
    eth_part = get_sctp_stack(sctp_data)
    return eth_part


def get_sccp_stack(data):
    # hex: "010001010000009c00060008000000010210008900000065000015b0030200070900030e190b12080a12041808390100000b12080a12045383160002005b6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619000000"
    padding_len = (len(data) + 4) % 4
    if padding_len != 0:
        padding_len = 4 - padding_len
    #   padding_len = 3
    print("padding len is %d" % padding_len)
    padding = b"\x00" * padding_len
    parameter_length = 16 + len(data)
    parameter_length_field = "%04x" % (parameter_length)
    m3ua_length = parameter_length + 18 + padding_len  # was 16
    m3ua_length_field = "%08x" % (m3ua_length)
    m3ua_data_hex = f"01000101{m3ua_length_field}00060008000000010210{parameter_length_field}00000065000015b003020007"
    sctp_data = binascii.a2b_hex(m3ua_data_hex) + bytes(data) + padding
    eth_part = get_sctp_stack(sctp_data)
    return eth_part


def get_ip_stack(data, protocol=99):
    ip_part = dpkt.ip.IP(
        src=b"\x0a\x0a\x0a\x0a",
        dst=b"\x0a\x0a\x0b\x0b",
        p=protocol,
        len=20 + len(data),
        data=data,
    )

    eth_part = dpkt.ethernet.Ethernet(
        #                                     src = eth_pkt.dst,
        #                                     dst = eth_pkt.src,
        data=ip_part
    )
    return eth_part


def get_ethernet_stack(data):
    eth_part = dpkt.ethernet.Ethernet(
        #                                     src = eth_pkt.dst,
        #                                     dst = eth_pkt.src,
        data=data
    )
    return eth_part


def make_pcap(pkt, linktype=dpkt.pcap.DLT_EN10MB):
    fh_pcap = io.BytesIO()
    pcap_writer = dpkt.pcap.Writer(fh_pcap, linktype=linktype)
    pcap_writer.writepkt(pkt)
    return fh_pcap.getvalue()


def test_ip():
    response = get_ip_stack(b"1234567")
    assert response.data.data == b"1234567"


def test_sctp():
    response = get_sctp_stack(b"1234")
    assert response.data.data[-4:] == b"1234"


def test_tcap():
    response = get_tcap_stack(b"1234")
    assert response.data.data[-6:] == b"1234\x00\x00"
    response = get_tcap_stack(b"12345")
    assert response.data.data[-6:] == b"12345\x00"


def test_udp():
    response = get_udp_stack(data=b"123")
    assert response.data.data.data == b"123"


def test_tcp():
    response = get_tcp_stack(tcp_data=b"12345678")
    assert response.data.data.data == b"12345678"


if __name__ == "__main__":
    http = get_tcp_stack(tcp_data=b"GET /\r\n\r\n\r\n")
    print("generated http request: %s" % repr(http))
    print("raw: %s" % (repr(str(http))))
    pcap_str = make_pcap(http)
    print("raw pcap: %s" % (repr(str(pcap_str))))
    fh = open("xx.pcap", "wb")
    fh.write(bytes(pcap_str))
    fh.close()
