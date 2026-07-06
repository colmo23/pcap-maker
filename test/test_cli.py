import io
import dpkt
import pytest
from pcap_maker import cli


def test_do_tcp_pcap():
    args = cli.build_parser().parse_args(
        ["tcp", "--hex", "474554202f20485454502f312e310d0a0d0a", "--dport", "80"]
    )
    pcap_bytes = bytes(cli.do_tcp_pcap(args))
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(pcap_bytes))
    _, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth.data.data, dpkt.tcp.TCP)


def test_do_tcap_pcap():
    args = cli.build_parser().parse_args(["tcap", "--hex", "1234"])
    pcap_bytes = bytes(cli.do_tcap_pcap(args))
    pcap_reader = dpkt.pcap.Reader(io.BytesIO(pcap_bytes))
    _, buf = next(pcap_reader)
    eth = dpkt.ethernet.Ethernet(buf)
    assert isinstance(eth.data.data, dpkt.sctp.SCTP)


def test_main_writes_file(tmp_path):
    output = tmp_path / "out.pcap"
    rc = cli.main(
        ["ethernet", "--hex", "aabbccddeeff", "-o", str(output)]
    )
    assert rc == 0
    assert output.exists()
    assert output.stat().st_size > 0


def test_main_invalid_hex(capsys):
    rc = cli.main(["tcp", "--hex", "zz"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "invalid hex input" in captured.err


def test_protocol_required():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])
