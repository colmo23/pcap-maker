from bottle import route, run, get, post, request, redirect, response
import binascii
import pcap_utils

@route('/')
def all():
    return '''
        <a href="/tcp">TCP</a>
        <a href="/udp">UDP</a>
        <a href="/sctp">SCTP</a>
        <a href="/ip">IP</a>
    '''
      


@get('/tcp') 
def get_tcp_network_info():
    return '''
        <form action="/tcp" method="post">
            dest port: <input name="dport" type="text" value="80" type="number" min="0" step="1" max="65535"/>
            tcp hex data: <input name="tcphex" type="textarea" />
            <input value="Generate PCAP" type="submit" />
        </form>

        <p>sample:</p>
        </br>
        <p>474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a</p>
    '''

@post('/tcp')
def do_tcp_pcap():
    dport = request.forms.get('dport')
    dport = int(dport)
    tcp_hex = request.forms.get('tcphex')
    tcp_data = binascii.a2b_hex(tcp_hex)
    pkt = pcap_utils.get_tcp_stack(tcp_data = tcp_data, tcp_dest_port = dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    
    return bytes(pcap_obj)

@get('/udp') 
def get_udp_network_info():
    return '''
        <form action="/udp" method="post">
            dest port: <input name="dport" type="text" value="161" type="number" min="0" step="1" max="65535"/>
            tcp hex data: <input name="udphex" type="textarea" />
            <input value="Generate PCAP" type="submit" />
        </form>

        <p>sample:</p>
        </br>
        <p>SNMP GET (use dest port of 161):</p>
        <p>307902010004067075626c6963a26c0201290201000201003061302106122b06010401817d0840040201070a86deb738040b3137322e33312e31392e32302306122b06010401817d0840040201070a86deb736040d3235352e3235352e3235352e30301706122b06010401817d0840040201050a86deb960020101</p>
    '''

@post('/udp')
def do_udp_pcap():
    dport = request.forms.get('dport')
    dport = int(dport)
    hexvalue = request.forms.get('udphex')
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_udp_stack(data = data, dest_port = dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    
    return bytes(pcap_obj)

@get('/sctp') 
def get_sctp_network_info():
    return '''
        <form action="/sctp" method="post">
            source port: <input name="sport" type="text" value="2905" type="number" min="0" step="1" max="65535"/>
            dest port: <input name="dport" type="text" value="2905" type="number" min="0" step="1" max="65535"/>
            SCTP hex data: <input name="sctphex" type="textarea" />
            <input value="Generate PCAP" type="submit" />
        </form>

        <p>sample:</p>
        </br>
        <p>M3UA DATA (use dest port of 2905):</p>
        <p>010001010000005400020049c583af405bd5000100a0010a02020705819084190f0a070317933393798008018003057c038890a61d038890a6310200643f06039300060010f4056476c328813902f49000000000</p>
        <p>010001010000005400020049c583af405bd5000100a0010a02020705819084190f0a070317933393798008018003057c038890a61d038890a6310200643f06039300060010f4056476c328813902f49000000000</p>
    '''

@post('/sctp')
def do_sctp_pcap():
    sport = request.forms.get('sport')
    sport = int(sport)
    dport = request.forms.get('dport')
    dport = int(dport)
    hexvalue = request.forms.get('sctphex')
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_sctp_stack(data = data, src_port = sport, dest_port = dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    
    return bytes(pcap_obj)

@get('/ip') 
def get_ip_network_info():
    return '''
        <form action="/ip" method="post">
            protocol: <input name="protocol" type="text" value="132" type="number" min="0" step="1" max="65535"/>
            IP payload hex data: <input name="iphex" type="textarea" />
            <input value="Generate PCAP" type="submit" />
        </form>

        <p>sample:</p>
        </br>
        <p>SCTP/M3UA DATA (use protocol of 132):</p>
        <p>189f0b5add68d33d40ed9bde00030018d42b489200000000000000030100030400000008</p>
    '''

@post('/ip')
def do_ip_pcap():
    protocol = request.forms.get('protocol')
    protocol = int(protocol)
    hexvalue = request.forms.get('iphex')
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_ip_stack(data = data, protocol = protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    
    return bytes(pcap_obj)

run(host='localhost', port=8080, debug=True)
