import binascii
import dpkt
import io
import struct



def get_tcp_stack(tcp_data, src_ip = b"\x0a\x0a\x0a\x0a", dest_ip = b"\x0a\x0a\x0a\x10", tcp_src_port = 1000, tcp_dest_port = 80):

    tcp_part = dpkt.tcp.TCP(sport = tcp_src_port, dport = tcp_dest_port, data = tcp_data)
    
    ip_part = dpkt.ip.IP(
                         src = src_ip,
                         dst = dest_ip,
                         p = dpkt.ip.IP_PROTO_TCP,
                         len = 20 + len(str(tcp_part)),
                         data = tcp_part)

    eth_part = dpkt.ethernet.Ethernet(
#                                     src = eth_pkt.dst,
#                                     dst = eth_pkt.src,
                                      data = ip_part)
    return eth_part


def get_udp_stack(data, src_ip = b"\x0a\x0a\x0a\x0a", dest_ip = b"\x0a\x0a\x0a\x10", src_port = 1000, dest_port = 80):

    l3_part = dpkt.udp.UDP(sport = src_port, dport = dest_port, ulen = 8 + len(data), data = data)
    
    ip_part = dpkt.ip.IP(
                         src = src_ip,
                         dst = dest_ip,
                         p = dpkt.ip.IP_PROTO_UDP,
                         len = 20 + len(str(l3_part)),
                         data = l3_part)

    eth_part = dpkt.ethernet.Ethernet(
#                                     src = eth_pkt.dst,
#                                     dst = eth_pkt.src,
                                      data = ip_part)
    return eth_part

def get_sctp_stack(data, src_ip = b"\x0a\x0a\x0a\x0a", dest_ip = b"\x0a\x0a\x0a\x10", src_port = 2905, dest_port = 2905, protocol = 3):

    data_chunk = dpkt.sctp.Chunk(type = dpkt.sctp.DATA)
    chunk_tsn = b"\x00\x10\x20\x30"
    chunk_stream_id = b"\x00\x80"
    chunk_protocol_id = struct.pack("!i",protocol)
    chunk_seq = b"\x00\x2a"


    data_chunk.data = chunk_tsn + chunk_stream_id + chunk_seq + chunk_protocol_id + bytes(data) 

    padding_len = 4 - (len(data_chunk.data) % 4)
    data_chunk.padding = b'\x00' * padding_len
    data_chunk.len = len(data_chunk.data) + padding_len

    data_chunk.flags = 0x03
    l3_part = dpkt.sctp.SCTP(sport = src_port, dport = dest_port)
    l3_part.chunks = [data_chunk]
    
    l3_part_bytes = bytes(l3_part)
    ip_part = dpkt.ip.IP(
                         src = src_ip,
                         dst = dest_ip,
                         p = dpkt.ip.IP_PROTO_SCTP,
                         len = 20 + len(l3_part_bytes),
                         data = l3_part_bytes)

    eth_part = dpkt.ethernet.Ethernet(
#                                     src = eth_pkt.dst,
#                                     dst = eth_pkt.src,
                                      data = ip_part)
    return eth_part

def get_ip_stack(data, protocol = 99):

    ip_part = dpkt.ip.IP(
                         src = b'\x0a\x0a\x0a\x0a',
                         dst = b'\x0a\x0a\x0b\x0b',
                         p = protocol,
                         len = 20 + len(data),
                         data = data)

    eth_part = dpkt.ethernet.Ethernet(
#                                     src = eth_pkt.dst,
#                                     dst = eth_pkt.src,
                                      data = ip_part)
    return eth_part



def make_pcap(pkt):
    fh = io.BytesIO()
    pcap_writer = dpkt.pcap.Writer(fh)
    pcap_writer.writepkt(pkt)
    return fh.getvalue()



if __name__ == '__main__':
    http = get_tcp_stack(tcp_data = b"GET /\r\n\r\n\r\n")
    print("generated http request: %s" % repr(http))
    print("raw: %s" % (repr(str(http))))
    pcap_str = make_pcap(http)
    print("raw pcap: %s" % (repr(str(pcap_str))))
    fh = open("xx.pcap", "wb")
    fh.write(bytes(pcap_str))
    fh.close()

