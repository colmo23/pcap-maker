from bottle import route, run, get, post, request, response
import binascii
import pcap_utils
import html_pieces


@route('/')
def all():
    header = html_pieces.HEADER
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, html_pieces.INFO)
    return header + body


@get('/tcp')
def get_tcp_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_TCP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@post('/tcp')
def do_tcp_pcap():
    dport = request.forms.get('dport')
    dport = int(dport)
    tcp_hex = request.forms.get('tcphex')
    tcp_hex = pcap_utils.cleanup_hex(tcp_hex)
    tcp_data = binascii.a2b_hex(tcp_hex)
    pkt = pcap_utils.get_tcp_stack(tcp_data=tcp_data, tcp_dest_port=dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    return bytes(pcap_obj)


@get('/udp')
def get_udp_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_UDP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@post('/udp')
def do_udp_pcap():
    dport = request.forms.get('dport')
    dport = int(dport)
    hexvalue = request.forms.get('udphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_udp_stack(data=data, dest_port=dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    return bytes(pcap_obj)


@get('/sctp')
def get_sctp_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_SCTP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@post('/sctp')
def do_sctp_pcap():
    sport = request.forms.get('sport')
    sport = int(sport)
    dport = request.forms.get('dport')
    dport = int(dport)
    protocol = request.forms.get('protocol')
    protocol = int(protocol)
    hexvalue = request.forms.get('sctphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_sctp_stack(data=data, src_port=sport, dest_port=dport, protocol=protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    return bytes(pcap_obj)


@get('/ip')
def get_ip_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_IP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@post('/ip')
def do_ip_pcap():
    protocol = request.forms.get('protocol')
    protocol = int(protocol)
    hexvalue = request.forms.get('iphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_ip_stack(data=data, protocol=protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    return bytes(pcap_obj)


@get('/full')
def get_full_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_FULL
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@post('/full')
def do_full_pcap():
    linktype = request.forms.get('linktype')
    linktype = int(linktype)
    hexvalue = request.forms.get('fullhex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pcap_obj = pcap_utils.make_pcap(data, linktype=linktype)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    return bytes(pcap_obj)


if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True)
