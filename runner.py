from bottle import route, run, get, post, request, redirect, response
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
    '''

@post('/')
def do_pcap():
    dport = request.forms.get('dport')
    dport = int(dport)
    tcp_hex = request.forms.get('tcphex')
    pkt = pcap_utils.get_tcp_stack(tcp_data = tcp_hex, tcp_dest_port = dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    response.content_type = 'application/cap'
    response.set_header("Content-Disposition", 'attachment; filename="x.pcap"')
    
    return str(pcap_obj)

run(host='localhost', port=8080, debug=True)
