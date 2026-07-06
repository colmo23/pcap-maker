# pcap-maker
 

## Install
Setup for development environment
```
python3 -m venv venv
source venv/bin/activate
pip install -e .[dev]
```
IF in a production environment replace the above pip command with this one:
```
pip install .
```

## Usage:

```
python3 -m pcap_maker.runner
```

## CLI

Generate a pcap directly from a hex dump, without running the web app.

```
python3 -m pcap_maker.cli <protocol> [--hex HEX | --file PATH] [-o output.pcap]
```

`<protocol>` is one of: `tcp`, `udp`, `sctp`, `sccp`, `tcap`, `ip`, `ethernet`, `full`.
If neither `--hex` nor `--file` is given, hex is read from stdin.

Examples:

```
# TCAP hex passed directly on the command line
python3 -m pcap_maker.cli tcap --hex "6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619" -o tcap.pcap

# TCP hex read from a file, custom destination port
python3 -m pcap_maker.cli tcp --file http_request.hex --dport 80 -o tcp.pcap

# hex piped in via stdin
cat snmp_get.hex | python3 -m pcap_maker.cli udp --dport 161 -o udp.pcap

# SCTP with a custom protocol id (2 = M2UA, 3 = M3UA)
python3 -m pcap_maker.cli sctp --hex "0100030100000008" --protocol 3 -o sctp.pcap
```

If `-o` is omitted, the file is written to `<protocol>-<date>.pcap` in the current directory.

If installed with `pip install .` / `pip install -e .`, the same tool is also available as the `pcap-maker` command, e.g. `pcap-maker tcap --hex ... -o tcap.pcap`.

## Unittests

```
pytest .
```

## Playwright tests
```
pip install pytest-playwright
playwright install chromium
pytest test/test_e2e.py
```

## Code reformatting

```
autopep8 --in-place --aggressive --aggressive pcap_maker/*py
```

```
black pcap_maker
```
## Code style
```
flake8 pcap_maker
```

```
pylint pcap_maker/*py
```


## CI tests
```
pip3 install tox
tox
```

