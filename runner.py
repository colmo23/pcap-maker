from bottle import route, run, get, post, request, redirect, response
import binascii
import pcap_utils

@route('/<path>')
def all(path):
    redirect("/")


@get('/') 
def get_network_info():
    return '''
        <form action="/" method="post">
            dest port: <input name="dport" type="text" />
            tcp hex data: <input name="tcphex" type="textarea" />
            <input value="Generate PCAP" type="submit" />
        </form>

        <p>sample:</p>
        </br>
        <p>474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a</p>
    '''

@post('/')
def do_pcap():
    dport = request.forms.get('dport')
    dport = int(dport)
    tcp_hex = request.forms.get('tcphex')
    tcp_data = binascii.a2b_hex(tcp_hex)
    pkt = pcap_utils.get_tcp_stack(tcp_data = tcp_data, tcp_dest_port = dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    
    return str(pcap_obj)

run(host='localhost', port=8080, debug=True)
