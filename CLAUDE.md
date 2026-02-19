# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Run the app:**
```bash
python3 -m pcap_maker.runner
```
Serves on `localhost:8080` with debug mode enabled.

**Run tests:**
```bash
pytest .
```

**Run a single test file:**
```bash
pytest test/test_pcap_utils.py
pytest test/test_runner.py
```

**Lint:**
```bash
flake8 pcap_maker
pylint pcap_maker/*py
```

**Format:**
```bash
autopep8 --in-place --aggressive --aggressive pcap_maker/*py
black pcap_maker
```

**Install for development:**
```bash
pip install -e .[dev]
```

## Architecture

The app is a Flask web UI for generating PCAP files from hex packet data. Users enter raw hex bytes for each layer, choose a protocol stack, and download the resulting `.pcap` file.

### Layers

- **`runner.py`** — Flask routes. Each protocol has a GET (render form) and POST (generate PCAP) route. POST handlers read form fields, call `pcap_utils` stack builders, then call `make_pcap()` and return the bytes as a file download.
- **`pcap_utils.py`** — Packet construction using `dpkt`. Contains `get_*_stack()` functions that build `dpkt.ethernet.Ethernet` objects from hex form fields, plus `make_pcap()` which wraps a packet in a PCAP container.
- **`templates/`** — Jinja2 templates. `_form.html` is the reusable form partial included by all protocol pages. Each protocol template (`tcp.html`, `udp.html`, etc.) provides the page title, field definitions, and sample hex payloads that populate the form.
- **`static/js/main.js`** — Hex editor: adds line numbers, an ASCII column, and auto-spacing to any `<textarea class="hex-input">`.

### Protocol stacks supported

| Route | Stack |
|-------|-------|
| `/tcp` | TCP / IP / Ethernet |
| `/udp` | UDP / IP / Ethernet |
| `/sctp` | SCTP / IP / Ethernet |
| `/sccp` | SCCP / M3UA / SCTP / IP / Ethernet |
| `/tcap` | TCAP / M3UA / SCTP / IP / Ethernet |
| `/ip` | IP / Ethernet (custom protocol number) |
| `/ethernet` | Ethernet (raw) |
| `/full` | User-specified linktype with raw payload |

### Adding a new protocol

1. Add a `get_<proto>_stack()` function in `pcap_utils.py` returning a `dpkt.ethernet.Ethernet` object.
2. Add GET and POST routes in `runner.py`.
3. Create a template `<proto>.html` that includes `_form.html` with the field list.
4. Add the nav link in `base.html`.
