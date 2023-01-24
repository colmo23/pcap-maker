from bottle import route, run, get, post, request, redirect, response
import binascii
import pcap_utils
import html_pieces

TOP_LINKS = ''' 
        <a href="/tcp">TCP</a>
        <a href="/udp">UDP</a>
        <a href="/sctp">SCTP</a>
        <a href="/ip">IP</a>
        <a href="/full">Full protocol stack</a>
        <a href="/test">Test page</a>
        <br/>
    '''



@route('/')
def all():
    return TOP_LINKS
      


@get('/tcp') 
def get_tcp_network_info():
    return TOP_LINKS + '''
        <form action="/tcp" method="post">
            dest port: <input name="dport" type="text" value="80" type="number" min="0" step="1" max="65535" size="5"/>
            tcp hex data: <textarea name="tcphex" type="textarea" rows="4" cols="80"></textarea>
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
    return TOP_LINKS + '''
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
    return TOP_LINKS + '''
        <form action="/sctp" method="post">
            source port: <input name="sport" type="text" value="2905" type="number" min="0" step="1" max="65535"/>
            dest port: <input name="dport" type="text" value="2905" type="number" min="0" step="1" max="65535"/>
            protocol id (M3uA=3,M2UA=2): <input name="protocol" type="text" value="3" type="number" min="0" step="1" max="65535"/>
            SCTP hex data: <input name="sctphex" type="textarea" />
            <input value="Generate PCAP" type="submit" />
        </form>

        <h2>Samples</h2>
        </br>
        <p>M3UA DATA (use dest port of 2905):</p>
        <p>0100030100000008</p>
        <p>m3ua/sccp/tcap begin/ati</p>
        <p>0100010100000094000600080000003302100081000003e8000003e903000013098103101c0d120600710479510001000016000c12930011045383171111110150624e4804733b33c96b1e281c060700118605010101a011600f80020780a109060704000001001d036c26a124020147020147301ca00a800844500101000016f0a10480008100830891538307000000f1000000</p>
        <p>m2pa/sccp/tcap/ussd (use protocol of 2)</p>
        <p>010006010000009c0300009283286204210900030d180a129300110472281906000b12060011047228196041066c626a48042f3b46026b3a2838060700118605010101a02d602b80020780a109060704000001001302be1a2818060704000001010101a00da00b80099656051124006913f66c26a12402010102013b301c04010f040eaa180da682dd6c31192d36bbdd468007917267415827f20000</p>
    '''

@post('/sctp')
def do_sctp_pcap():
    sport = request.forms.get('sport')
    sport = int(sport)
    dport = request.forms.get('dport')
    dport = int(dport)
    protocol = request.forms.get('protocol')
    protocol = int(protocol)
    hexvalue = request.forms.get('sctphex')
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_sctp_stack(data = data, src_port = sport, dest_port = dport, protocol = protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    
    return bytes(pcap_obj)

@get('/ip') 
def get_ip_network_info():
    return TOP_LINKS + '''
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


@get('/full') 
def get_full_network_info():
    return TOP_LINKS + '''
        <form action="/full" method="post">
            Full stack hex data: <input name="fullhex" type="textarea" />
            <input value="Generate PCAP" type="submit" />
        </form>

        <p>sample:</p>
        </br>
        <p>ethernet.io.sctp.m3ua</p>
        <p>00005096523a0026cb39f4c0080045000068da010000fa844c7e585206860aad300d189f0b5add68d33d40ed9bde00030018d42b48920000000000000003010003040000000800030030d42b489300000001000000030100000100000020000d000800010002001100080000000d0006000800000456</p>
    '''

@post('/full')
def do_full_pcap():
    hexvalue = request.forms.get('fullhex')
    data = binascii.a2b_hex(hexvalue)
    pcap_obj = pcap_utils.make_pcap(data)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    return bytes(pcap_obj)




@get('/test') 
def get_test_network_info():
    header = html_pieces.HEADER
    form = html_pieces.FORM
    body = "<body>%s</body></hrml>" % form
    return header + body

@post('/test')
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

run(host='localhost', port=8080, debug=True)
