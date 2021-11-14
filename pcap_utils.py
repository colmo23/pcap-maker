import dpkt
import io



def get_tcp_stack(tcp_data, src_ip = "\x0a\x0a\x0a\x0a", dest_ip = "\x0a\x0a\x0a\x10", tcp_src_port = 1000, tcp_dest_port = 80):

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


def make_pcap(pkt):
    fh = io.BytesIO()
    pcap_writer = dpkt.pcap.Writer(fh)
    pcap_writer.writepkt(pkt)
    return fh.getvalue()



if __name__ == '__main__':
    http = get_tcp_stack(tcp_data = "GET /\r\n\r\n\r\n")
    print("generated http request: %s" % repr(http))
    print("raw: %s" % (repr(str(http))))
    pcap_str = make_pcap(http)
    print("raw pcap: %s" % (repr(str(pcap_str))))
    fh = open("xx.pcap", "wb")
    fh.write(str(pcap_str))
    fh.close()

