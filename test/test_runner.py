import pytest
import dpkt
import io
from pcap_maker import runner

@pytest.fixture
def client():
    runner.app.config['TESTING'] = True
    with runner.app.test_client() as client:
        yield client

def test_root_page(client):
    rv = client.get('/')
    assert rv.status_code == 200
    assert b'pcap file' in rv.data

@pytest.mark.parametrize("path, expected_content", [
    ("/ethernet", b"Ethernet hex payload"),
    ("/tcp", b"TCP hext payload"),
    ("/udp", b"UDP hex payload"),
    ("/sctp", b"SCTP hex payload"),
    ("/tcap", b"TCAP hex payload"),
    ("/sccp", b"SCCP hex payload"),
    ("/ip", b"IP hex payload"),
    ("/full", b"Full hex payload"),
])
def test_get_pages(client, path, expected_content):
    rv = client.get(path)
    assert rv.status_code == 200
    assert expected_content in rv.data

def test_post_ethernet(client):
    rv = client.post('/ethernet', data=dict(
        ethernethex='4500005e000000004006526d0a0a0a0a0a0a0a1003e80050deadbeef000000005002ffffe6b90000474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="ethernet.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth, dpkt.ethernet.Ethernet)

def test_post_tcp(client):
    rv = client.post('/tcp', data=dict(
        dport='80',
        tcphex='474554202f20485454502f312e310d0a486f73743a20686f73743a706f72740d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="tcp.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth.data.data, dpkt.tcp.TCP)

def test_post_udp(client):
    rv = client.post('/udp', data=dict(
        dport='53',
        udphex='43130100000100000000000003616f6c03636f6d0000010001'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="udp.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth.data.data, dpkt.udp.UDP)

def test_post_sctp(client):
    rv = client.post('/sctp', data=dict(
        sport='2905',
        dport='2905',
        protocol='3',
        sctphex='0100030100000008'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="sctp.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth.data.data, dpkt.sctp.SCTP)

def test_post_tcap(client):
    rv = client.post('/tcap', data=dict(
        tcaphex='6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="tcap.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    # TCAP is over SCTP in this implementation
    assert isinstance(eth.data.data, dpkt.sctp.SCTP)

def test_post_sccp(client):
    rv = client.post('/sccp', data=dict(
        sccphex='0900030e190b12080a12041808390100000b12080a12045383160002005b6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="sccp.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    # SCCP is over SCTP in this implementation
    assert isinstance(eth.data.data, dpkt.sctp.SCTP)

def test_post_ip(client):
    rv = client.post('/ip', data=dict(
        protocol='132',
        iphex='189f0b5add68d33d40ed9bde00030018d42b489200000000000000030100030400000008'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="ip.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth.data, dpkt.ip.IP)

def test_post_full(client):
    rv = client.post('/full', data=dict(
        linktype='1',
        fullhex='00005096523a0026cb39f4c0080045000068da010000fa844c7e585206860aad300d189f0b5add68d33d40ed9bde00030018d42b48920000000000000003010003040000000800030030d42b489300000001000000030100000100000020000d000800010002001100080000000d0006000800000456'
    ))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'] == 'application/cap'
    assert rv.headers['Content-Disposition'] == 'attachment; filename="full.pcap"'
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(rv.data))
    ts, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth, dpkt.ethernet.Ethernet)
