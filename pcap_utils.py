import dpkt


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




if __name__ == '__main__':
    http = get_tcp_stack(tcp_data = "GET /\r\n\r\n\r\n")
    import pdb;pdb.set_trace()
