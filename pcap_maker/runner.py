#!/usr/bin/env python3

import binascii
import pcap_utils
import html_pieces

from flask import Flask, request, make_response
app = Flask(__name__)


@app.route('/')
def all():
    header = html_pieces.HEADER
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, html_pieces.INFO)
    return header + body

@app.get('/ethernet')
def get_ethernet_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_ETHERNET
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/ethernet')
def do_ethernet_pcap():
    ethernet_hex = request.form.get('ethernethex')
    ethernet_hex = pcap_utils.cleanup_hex(ethernet_hex)
    ethernet_data = binascii.a2b_hex(ethernet_hex)
    pkt = pcap_utils.get_ethernet_stack(data=ethernet_data)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="ethernet.pcap"')
    return response

@app.get('/tcp')
def get_tcp_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_TCP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/tcp')
def do_tcp_pcap():
    dport = request.form.get('dport')
    dport = int(dport)
    tcp_hex = request.form.get('tcphex')
    tcp_hex = pcap_utils.cleanup_hex(tcp_hex)
    tcp_data = binascii.a2b_hex(tcp_hex)
    pkt = pcap_utils.get_tcp_stack(tcp_data=tcp_data, tcp_dest_port=dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="tcp.pcap"')
    return response


@app.get('/udp')
def get_udp_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_UDP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/udp')
def do_udp_pcap():
    dport = request.form.get('dport')
    dport = int(dport)
    hexvalue = request.form.get('udphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_udp_stack(data=data, dest_port=dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="udp.pcap"')
    return response


@app.get('/sctp')
def get_sctp_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_SCTP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/sctp')
def do_sctp_pcap():
    sport = request.form.get('sport')
    sport = int(sport)
    dport = request.form.get('dport')
    dport = int(dport)
    protocol = request.form.get('protocol')
    protocol = int(protocol)
    hexvalue = request.form.get('sctphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_sctp_stack(data=data, src_port=sport, dest_port=dport, protocol=protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="sctp.pcap"')
    return response


@app.get('/tcap')
def get_tcap_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_TCAP
    body = "<body>%s%s</body></html>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/tcap')
def do_tcap_pcap():
    hexvalue = request.form.get('tcaphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_tcap_stack(data=data)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="tcap.pcap"')
    return response

@app.get('/sccp')
def get_sccp_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_SCCP
    body = "<body>%s%s</body></html>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/sccp')
def do_sccp_pcap():
    hexvalue = request.form.get('sccphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_sccp_stack(data=data)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="sccp.pcap"')
    return response


@app.get('/ip')
def get_ip_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_IP
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/ip')
def do_ip_pcap():
    protocol = request.form.get('protocol')
    protocol = int(protocol)
    hexvalue = request.form.get('iphex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_ip_stack(data=data, protocol=protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="ip.pcap"')
    return response


@app.get('/full')
def get_full_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM_FULL
    body = "<body>%s%s</body></hrml>" % (html_pieces.TOP_LINKS, form)
    return header + body


@app.post('/full')
def do_full_pcap():
    linktype = request.form.get('linktype')
    linktype = int(linktype)
    hexvalue = request.form.get('fullhex')
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pcap_obj = pcap_utils.make_pcap(data, linktype=linktype)
    response = make_response(bytes(pcap_obj))
    response.headers.set('Content-type', 'application/cap')
    response.headers.set("Content-Disposition", 'attachment; filename="full.pcap"')
    return response


if __name__ == "__main__":
    # Used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host="localhost", port=8080, debug=True)
