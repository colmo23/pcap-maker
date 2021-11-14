from bottle import route, run, get, post, request
import pcap_utils


@get('/') # or @route('/login')
def get_network_info():
    return '''
        <form action="/" method="post">
            dest port: <input name="dport" type="text" />
            tcp hex data: <input name="tcphex" type="text" />
            <input value="Generate PCAP" type="submit" />
        </form>
    '''

@post('/') # or @route('/login', method='POST')
def do_pcap():
    dport = request.forms.get('dport')
    dport = int(dport)
    tcp_hex = request.forms.get('tcphex')
    pcap_obj = pcap_utils.get_tcp_stack(tcp_data = tcp_hex, tcp_dest_port = dport)
    
    return "<p>Your information was %s - %s - %s</p>" % (dport, tcp_hex, repr(str(pcap_obj)))

run(host='localhost', port=8080, debug=True)
