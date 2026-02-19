#!/usr/bin/env python3

"runner"

import binascii
from datetime import date
from . import pcap_utils

from flask import Flask, request, make_response, render_template

app = Flask(__name__)


def make_filename(protocol, pcap_bytes):
    today = date.today().strftime('%Y%m%d')
    return f"{protocol}-{today}-{len(pcap_bytes)}.pcap"


@app.route("/")
def root_page():
    return render_template("index.html")


@app.get("/ethernet")
def get_ethernet_network_info():
    form_fields = [
        {
            "name": "ethernethex",
            "label": "Ethernet hex payload",
            "type": "textarea",
            "placeholder": "Ethernet hex (see below for examples)",
        }
    ]
    samples = [
        {
            "title": "ip/sctp/m3ua <br/>",
            "data": "00005096523a0026cb39f4c0080045000068da010000fa844c7e585206860aad300d189f0b5add68d33d40ed9bde00030018d42b48920000000000000003010003040000000800030030d42b489300000001000000030100000100000020000d000800010002001100080000000d0006000800000456",
        },
        {
            "title": "ip/tcp/http <br/>",
            "data": "4500005e000000004006526d0a0a0a0a0a0a0a1003e80050deadbeef000000005002ffffe6b90000474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a",
        },
    ]
    return render_template(
        "ethernet.html",
        form_id="ethernet_form",
        action="/ethernet",
        form_fields=form_fields,
        validation_field_id="ethernethex",
        validation_error_id="ethernethex_error",
        samples=samples,
    )


@app.post("/ethernet")
def do_ethernet_pcap():
    ethernet_hex = request.form.get("ethernethex")
    ethernet_hex = pcap_utils.cleanup_hex(ethernet_hex)
    ethernet_data = binascii.a2b_hex(ethernet_hex)
    # TODO could add a protocol type field (currently is hard coded to 0x0800
    # IP)
    pkt = pcap_utils.get_ethernet_stack(data=ethernet_data)
    pcap_obj = pcap_utils.make_pcap(pkt)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("ethernet", pcap_bytes)}"')
    return response


@app.get("/tcp")
def get_tcp_network_info():
    form_fields = [
        {
            "name": "dport",
            "label": "Destination port",
            "type": "number",
            "value": "80",
            "min": "0",
            "step": "1",
            "max": "65535",
            "size": "5",
        },
        {
            "name": "tcphex",
            "label": "TCP hext payload",
            "type": "textarea",
            "placeholder": "TCP hex (see below for examples)",
        },
    ]
    samples = [
        {
            "title": "HTTP GET example",
            "data": "474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a",
        },
        {
            "title": "HTTP2 example",
            "data": "485454502f312e312031303120537769746368696e672050726f746f636f6c730d0a436f6e6e656374696f6e3a20557067726164650d0a557067726164653a206832630d0a0d0a000012040000000000000300000064000400100000000100002000",
        },
        {
            "title": "MMS example",
            "data": "504f5354202f6d6d732f776170656e6320485454502f312e310d0a486f73743a2031302e3230302e3130302e30300d0a507261676d613a206e6f2d63616368650d0a4163636570743a206170706c69636174696f6e2f766e642e7761702e6d6d732d6d6573736167650d0a4163636570742d436861727365743a202a0d0a582d5761702d50726f66696c653a20687474703a2f2f6970686f6e656d6d732e6170706c652e636f6d2f6970686f6e652f756170726f662d324d422e7264660d0a4163636570742d4c616e67756167653a202a0d0a4163636570742d456e636f64696e673a206964656e746974790d0a436f6e74656e742d547970653a206170706c69636174696f6e2f766e642e7761702e6d6d732d6d6573736167650d0a436f6e74656e742d4c656e6774683a203630360d0a557365722d4167656e743a206950686f6e654f532f31362e332e3120283230443637290d0a6e756c6c3a20687474703a2f2f6d6d732e677072732e6162636465662e636f6d2f0d0a782d75702d7375626e6f3a20313238363830303030305f616263646566707573682e677072732e6162636465662e636f6d0d0a782d75702d63616c6c696e672d6c696e652d69643a2031393035353430303030300d0a782d75702d63682d7367736e69703a2037342e3139382e37302e3031330d0a782d75702d7261742d747970653a2030360d0a782d75702d737562736372696265722d636f733a2030310d0a43616368652d436f6e74726f6c3a206e6f2d63616368650d0a0d0a8c8098313637373030303030302d3135008d9397178331323839323434303030302f545950453d504c4d4e0097178331353139383032303030302f545950453d504c4d4e0097178331393035393231303030302f545950453d504c4d4e0097178331393035353431303030302f545950453d504c4d4e0097178331323839343432303030302f545950453d504c4d4e00890181841bb3896170706c69636174696f6e2f736d696c008a302e736d696c00021a822a6170706c69636174696f6e2f736d696c00c022302e736d696c003c736d696c3e0a3c686561643e0a3c6c61796f75743e0a203c726f6f742d6c61796f75742f3e0a3c726567696f6e2069643d22546578742220746f703d2237302522206c6566743d22302522206865696768743d22333025222077696474683d223130302522206669743d227363726f6c6c222f3e0a3c726567696f6e2069643d22496d6167652220746f703d22302522206c6566743d22302522206865696768743d22373025222077696474683d223130302522206669743d226d656574222f3e0a3c2f6c61796f75743e0a3c2f686561643e0a3c626f64793e0a3c706172206475723d22353030306d73223e0a3c696d67207372633d22302e6a70672220726567696f6e3d22496d616765222f3e0a3c74657874207372633d22302e7478742220726567696f6e3d2254657874222f3e0a3c2f7061723e0a3c2f626f64793e0a3c2f736d696c3e021a822a6170706c69636174696f6e2f736d696c00c022302e6d6d7300",
        },
    ]
    return render_template(
        "tcp.html",
        form_id="tcp_form",
        action="/tcp",
        form_fields=form_fields,
        validation_field_id="tcphex",
        validation_error_id="tcphex_error",
        samples=samples,
    )


@app.post("/tcp")
def do_tcp_pcap():
    dport = request.form.get("dport")
    dport = int(dport)
    tcp_hex = request.form.get("tcphex")
    tcp_hex = pcap_utils.cleanup_hex(tcp_hex)
    tcp_data = binascii.a2b_hex(tcp_hex)
    pkt = pcap_utils.get_tcp_stack(tcp_data=tcp_data, tcp_dest_port=dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("tcp", pcap_bytes)}"')
    return response


@app.get("/udp")
def get_udp_network_info():
    form_fields = [
        {
            "name": "dport",
            "label": "Destination port",
            "type": "number",
            "value": "161",
            "min": "0",
            "step": "1",
            "max": "65535",
            "size": "5",
        },
        {
            "name": "udphex",
            "label": "UDP hex payload",
            "type": "textarea",
            "placeholder": "UDP hex (see below for examples)",
        },
    ]
    samples = [
        {
            "title": "SNMP GET (use dest port of 161)",
            "data": "307902010004067075626c6963a26c0201290201000201003061302106122b06010401817d0840040201070a86deb738040b3137322e33312e31392e32302306122b06010401817d0840040201070a86deb736040d3235352e3235352e3235352e30301706122b06010401817d0840040201050a86deb960020101",
        },
        {
            "title": "GTP v1 Create PDP Context Request (use dest port of 2123)",
            "data": "321000970000000000fe00000272020301000000f00372f230fffeff0e5d0ffc10372f000011372f00001405800002f121830010036d6d73086d796d6574656f7202696584002280c0230b0100000b026d790377617080211001000010810600000000830600000000850004d481410d850004d48141178600079153830000000087000c0223621f9396585874fbffff970001029a00085389011058985321",
        },
        {
            "title": "GTP v1 - small example (use dest port of 2123)",
            "data": "3210001c000000009dbc00000215807922060357f00ffc108513c02a",
        },
        {
            "title": "DNS request (use dest port of 53)",
            "data": "43130100000100000000000003616f6c03636f6d0000010001",
        },
        {
            "title": "SIP request",
            "data": "5245474953544552207369703a742e766f6e63702e636f6d3a3130303030205349502f322e300d0a4d61782d466f7277617264733a2037300d0a436f6e74656e742d4c656e6774683a20300d0a5669613a205349502f322e302f554450203139322e3136382e312e36343a31303030303b6272616e63683d7a39684734624b3538626632303161300d0a43616c6c2d49443a206531383762616265356139313761613564653036613430623031663539623235403139322e3136382e312e36340d0a46726f6d3a2022313631373837363631313122203c7369703a313631373837363631313140742e766f6e63702e636f6d3a31303030303e3b7461673d3966626233656339653439623864350d0a546f3a2022313631373837363631313122203c7369703a313631373837363631313140742e766f6e63702e636f6d3a31303030303e0d0a435365713a203734353638343531352052454749535445520d0a436f6e746163743a2022313631373837363631313122203c7369703a3136313738373636313131403139322e3136382e312e36343a31303030303b7472616e73706f72743d7564703e3b657870697265733d32300d0a416c6c6f773a20494e564954452c2041434b2c2043414e43454c2c204259452c204e4f544946592c2052454645522c204f5054494f4e532c205550444154452c20505241434b0d0a417574686f72697a6174696f6e3a44696765737420726573706f6e73653d223766366565643731666364393235356266396666613537356634343631373035222c757365726e616d653d223136313738373636313131222c7265616c6d3d223231362e3131352e32302e313433222c6e6f6e63653d2231353330353333343134222c616c676f726974686d3d4d44352c7572693d227369703a742e766f6e63702e636f6d3a31303030302220d0a557365722d4167656e743a2056445632312030303144443932453446363120322e382e315f312e342e37204c776f6f456b334743442f62636d3030314444393245344636312e786d6c0d0a0d0a",
        },
    ]
    return render_template(
        "udp.html",
        form_id="udp_form",
        action="/udp",
        form_fields=form_fields,
        validation_field_id="udphex",
        validation_error_id="udphex_error",
        samples=samples,
    )


@app.post("/udp")
def do_udp_pcap():
    dport = request.form.get("dport")
    dport = int(dport)
    hexvalue = request.form.get("udphex")
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_udp_stack(data=data, dest_port=dport)
    pcap_obj = pcap_utils.make_pcap(pkt)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("udp", pcap_bytes)}"')
    return response


@app.get("/sctp")
def get_sctp_network_info():
    form_fields = [
        {
            "name": "sport",
            "label": "Source port",
            "type": "number",
            "value": "2905",
            "min": "0",
            "step": "1",
            "max": "65535",
            "size": "5",
        },
        {
            "name": "dport",
            "label": "Destination port",
            "type": "number",
            "value": "2905",
            "min": "0",
            "step": "1",
            "max": "65535",
            "size": "5",
        },
        {
            "name": "protocol",
            "label": "Protocol Id (3 means M3UA, 2 means M2UA)",
            "type": "number",
            "value": "3",
            "min": "0",
            "step": "1",
            "max": "65535",
            "size": "5",
        },
        {
            "name": "sctphex",
            "label": "SCTP hex payload",
            "type": "textarea",
            "placeholder": "SCTP hex (see below for examples)",
        },
    ]
    samples = [
        {
            "title": "M3UA DATA (use dest port of 2905)",
            "data": "0100030100000008",
        },
        {
            "title": "m3ua/sccp/tcap begin/ati",
            "data": "0100010100000094000600080000003302100081000003e8000003e903000013098103101c0d120600710479510001000016000c12930011045383171111110150624e4804733b33c96b1e281c060700118605010101a011600f80020780a109060704000001001d036c26a124020147020147301ca00a800844500101000016f0a10480008100830891538307000000f1000000",
        },
        {
            "title": "M2UA/SCCP/TCAP/USSD (use protocol of 2)",
            "data": "010006010000009c0300009283286204210900030d180a129300110472281906000b12060011047228196041066c626a48042f3b46026b3a2838060700118605010101a02d602b80020780a109060704000001001302be1a2818060704000001010101a00da00b80099656051124006913f66c26a12402010102013b301c04010f040eaa180da682dd6c31192d36bbdd468007917267415827f20000",
        },
        {
            "title": "M2UA/MTP3/SCCP/ANSI TCAP/SMS Delivery Point to Point (OTA) (use protocol of 2)",
            "data": "0100060100000060000100080000003e0300004e830a800400090003070b04430a0008044312000c35e233c70400000000e82be929cf0100d1020935f2209f69009f74009f81000108880516193204009f814101019f81430522222222220000",
        },
        {
            "title": "M2UA/MTP3/SCCP/TCAP/Camel Initial DP Arg (use protocol of 2)",
            "data": "01000601000000cc030000c1833001e8430981030d170a129200120422705700400a129200120422705700709c6281994804070004006b1a2818060700118605010101a00d600ba1090607040000010032016c75a173020101020100306b80016e8208839021721090000f830303975785010a8c06831407010900bb0580038090a39c01029d068314070109009e0203619f320806079209100491f9bf35038301119f360513fa3d3dea9f37069122705700709f39080250114231016500bf3b088106912270570070000000",
        },
        {
            "title": "M2UA/MTP3/SCCP/TCAP/GSM Process USSD (use protocol of 2)",
            "data": "010006010000009c0300009283286204210900030d180a129300110472281906000b12060011047228196041066c626a48042f3b46026b3a2838060700118605010101a02d602b80020780a109060704000001001302be1a2818060704000001010101a00da00b80099656051124006913f66c26a12402010102013b301c04010f040eaa180da682dd6c31192d36bbdd468007917267415827f20000",
        },
        {
            "title": "Diameter 3GPP Authentication Information Request (use protocol of 46)",
            "data": "010000d4c000013e0100002300002dc300043547000001150000000c0000000000000108000000346f7269676974686f73742e6570632e6d6e633035312e6d63633236322e336770706e6574776f726b2e6f726700000128000000296570632e6d6e633035312e6d63633236322e336770706e6574776f726b2e6f72670000000000011b000000296570632e6d6e633030392e6d63633230382e336770706e6574776f726b2e6f72670000000000000100000017353432393931313131313131313131000000057f8000000f000028af62125000",
        },
        {
            "title": "ISUP IAM message",
            "data": "010001010000003c0210003200000065000015b00502000b6f09010048000a030208060390551384000801000a0804137944141011113d010b000000",
        },
    ]
    return render_template(
        "sctp.html",
        form_id="sctp_form",
        action="/sctp",
        form_fields=form_fields,
        validation_field_id="sctphex",
        validation_error_id="sctphex_error",
        samples=samples,
    )


@app.post("/sctp")
def do_sctp_pcap():
    sport = request.form.get("sport")
    sport = int(sport)
    dport = request.form.get("dport")
    dport = int(dport)
    protocol = request.form.get("protocol")
    protocol = int(protocol)
    hexvalue = request.form.get("sctphex")
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_sctp_stack(data=data, src_port=sport, dest_port=dport, protocol=protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("sctp", pcap_bytes)}"')
    return response


@app.get("/tcap")
def get_tcap_network_info():
    form_fields = [
        {
            "name": "tcaphex",
            "label": "TCAP hex payload",
            "type": "textarea",
            "placeholder": "TCAP hex (see below for examples)",
        }
    ]
    samples = [
        {
            "title": "TCAP Begin MAP MO FSM",
            "data": "6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619",
        },
        {
            "title": "TCAP End Return Error",
            "data": "643c49035645066b262824060700118605010101a0196117a109060704000001001503a203020100a305a1030201006c0da30b02010102012030030a0105",
        },
    ]
    return render_template(
        "tcap.html",
        form_id="tcap_form",
        action="/tcap",
        form_fields=form_fields,
        validation_field_id="tcaphex",
        validation_error_id="tcaphex_error",
        samples=samples,
    )


@app.post("/tcap")
def do_tcap_pcap():
    hexvalue = request.form.get("tcaphex")
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_tcap_stack(data=data)
    pcap_obj = pcap_utils.make_pcap(pkt)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("tcap", pcap_bytes)}"')
    return response


@app.get("/sccp")
def get_sccp_network_info():
    form_fields = [
        {
            "name": "sccphex",
            "label": "SCCP hex payload",
            "type": "textarea",
            "placeholder": "SCCP hex (see below for examples)",
        }
    ]
    samples = [
        {
            "title": "TCAP Begin MAP MO FSM",
            "data": "0900030e190b12080a12041808390100000b12080a12045383160002005b6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619",
        },
        {
            "title": "TCAP Return Error",
            "data": "0900030e190b12080a12041808390100000b12080a12045383160002005b643c49035645066b262824060700118605010101a0196117a109060704000001001503a203020100a305a1030201006c0da30b02010102012030030a0105",
        },
        {
            "title": "TCAP Response Provide Roaming Number",
            "data": "0980030d170a120600120454045100000a120700120474141700004c644a49049b0001256b2a2828060700118605010101a01d611b80020780a109060704000001000303a203020100a305a1030201006c80a212020101300d020104300804069174141700000000",
        },
    ]
    return render_template(
        "sccp.html",
        form_id="sccp_form",
        action="/sccp",
        form_fields=form_fields,
        validation_field_id="sccphex",
        validation_error_id="sccphex_error",
        samples=samples,
    )


@app.post("/sccp")
def do_sccp_pcap():
    hexvalue = request.form.get("sccphex")
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_sccp_stack(data=data)
    pcap_obj = pcap_utils.make_pcap(pkt)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("sccp", pcap_bytes)}"')
    return response


@app.get("/ip")
def get_ip_network_info():
    form_fields = [
        {
            "name": "protocol",
            "label": "Protocol",
            "type": "number",
            "value": "3",
            "min": "0",
            "step": "1",
            "max": "65535",
            "size": "5",
        },
        {
            "name": "iphex",
            "label": "IP hex payload",
            "type": "textarea",
            "placeholder": "IP hex (see below for examples)",
        },
    ]
    samples = [
        {
            "title": "SCTP/M3UA DATA (use protocol of 132)",
            "data": "189f0b5add68d33d40ed9bde00030018d42b489200000000000000030100030400000008",
        }
    ]
    return render_template(
        "ip.html",
        form_id="ip_form",
        action="/ip",
        form_fields=form_fields,
        validation_field_id="iphex",
        validation_error_id="iphex_error",
        samples=samples,
    )


@app.post("/ip")
def do_ip_pcap():
    protocol = request.form.get("protocol")
    protocol = int(protocol)
    hexvalue = request.form.get("iphex")
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pkt = pcap_utils.get_ip_stack(data=data, protocol=protocol)
    pcap_obj = pcap_utils.make_pcap(pkt)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("ip", pcap_bytes)}"')
    return response


@app.get("/full")
def get_full_network_info():
    form_fields = [
        {
            "name": "linktype",
            "label": "Link Type",
            "type": "number",
            "value": "1",
            "min": "0",
            "step": "1",
            "max": "255",
            "size": "3",
        },
        {
            "name": "fullhex",
            "label": "Full hex payload",
            "type": "textarea",
            "placeholder": "Full hex (see below for examples)",
        },
    ]
    samples = [
        {
            "title": "Ethernet/io/sctp/m3ua <br/>(use linktype of 1)",
            "data": "00005096523a0026cb39f4c0080045000068da010000fa844c7e585206860aad300d189f0b5add68d33d40ed9bde00030018d42b48920000000000000003010003040000000800030030d42b489300000001000000030100000100000020000d000800010002001100080000000d0006000800000456",
        },
        {
            "title": "MTP3/SCCP/BSSAP/GSM  <br/>(use linktype of 141)",
            "data": "03443322db0693150300011f01001c03c504066004020005815e0581020055207e090005060027004004f1",
        },
        {
            "title": "MTP2/MTP3/ISUP IAM  <br/> (use linktype of 140)",
            "data": "1d1d2085024000900e00011100000a03020907039040380982990a06031317734508007989",
        },
        {
            "title": "Linux Cooked Capture/IP/UPD/VXLAN....  <br/> (use linktype of 113)",
            "data": "0000030400060000000000000000080045000075863140004011b6447f0000017f000001169d12b50061fe740800000000000100620deb01aa1efaaed0f78fdc080045000043000000004011a3103953300202136c329c40084b002f79e74822002308ca5b2974d6130056000d001806f2100fa106f210002e70035200010006030001000c00000000000000000000000000000000",
        },
    ]
    return render_template(
        "full.html",
        form_id="full_form",
        action="/full",
        form_fields=form_fields,
        validation_field_id="fullhex",
        validation_error_id="fullhex_error",
        samples=samples,
    )


@app.post("/full")
def do_full_pcap():
    linktype = request.form.get("linktype")
    linktype = int(linktype)
    hexvalue = request.form.get("fullhex")
    hexvalue = pcap_utils.cleanup_hex(hexvalue)
    data = binascii.a2b_hex(hexvalue)
    pcap_obj = pcap_utils.make_pcap(data, linktype=linktype)
    pcap_bytes = bytes(pcap_obj)
    response = make_response(pcap_bytes)
    response.headers.set("Content-type", "application/cap")
    response.headers.set("Content-Disposition", f'attachment; filename="{make_filename("full", pcap_bytes)}"')
    return response


if __name__ == "__main__":
    # Used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host="localhost", port=8080, debug=True)
