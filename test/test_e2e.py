"""
End-to-end browser tests using Playwright.

Setup (once):
    pip install pytest-playwright
    playwright install chromium

Run:
    pytest test/test_e2e.py
"""

import threading

import pytest

pytest.importorskip("playwright", reason="playwright not installed — run: pip install pytest-playwright && playwright install chromium")
from playwright.sync_api import Page, expect  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from pcap_maker.runner import app  # noqa: E402

BASE = "http://127.0.0.1:8081"


@pytest.fixture(scope="session")
def flask_server():
    """Start the Flask app on a dedicated port for the browser tests."""
    srv = make_server("127.0.0.1", 8081, app)
    t = threading.Thread(target=srv.serve_forever)
    t.daemon = True
    t.start()
    yield BASE
    srv.shutdown()


# ── Smoke tests ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "route",
    ["/", "/tcp", "/udp", "/sctp", "/tcap", "/sccp", "/ip", "/ethernet", "/full"],
)
def test_page_loads(page: Page, flask_server, route):
    response = page.goto(f"{BASE}{route}")
    assert response.status == 200


# ── Navigation ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "route,link_text",
    [
        ("/tcp", "TCP"),
        ("/udp", "UDP"),
        ("/sctp", "SCTP"),
        ("/ip", "IP"),
        ("/ethernet", "Ethernet"),
    ],
)
def test_nav_link_navigates(page: Page, flask_server, route, link_text):
    page.goto(BASE)
    page.get_by_role("link", name=link_text, exact=True).click()
    expect(page).to_have_url(f"{BASE}{route}")


# ── Hex editor ────────────────────────────────────────────────────────────────


def test_hex_editor_adds_spaces(page: Page, flask_server):
    """Hex input is auto-formatted with a space between each byte."""
    page.goto(f"{BASE}/tcp")
    page.locator(".hex-input").fill("aabbccdd")
    expect(page.locator(".hex-input")).to_have_value("aa bb cc dd")


def test_hex_editor_wraps_long_input(page: Page, flask_server):
    """Input longer than 16 bytes wraps onto a second line."""
    page.goto(f"{BASE}/tcp")
    page.locator(".hex-input").fill("aa" * 17)
    assert "\n" in page.locator(".hex-input").input_value()


# ── Clear button ──────────────────────────────────────────────────────────────


def test_clear_button_empties_field(page: Page, flask_server):
    page.goto(f"{BASE}/tcp")
    textarea = page.locator(".hex-input")
    textarea.fill("aabbccdd")
    page.locator(".clear-btn").click()
    expect(textarea).to_have_value("")


# ── Sample buttons ────────────────────────────────────────────────────────────


def test_use_sample_populates_field(page: Page, flask_server):
    page.goto(f"{BASE}/tcp")
    page.locator(".use-btn").first.click()
    assert len(page.locator(".hex-input").input_value().strip()) > 0


def test_copy_sample_shows_feedback(page: Page, flask_server):
    page.goto(f"{BASE}/tcp")
    copy_btn = page.locator(".copy-btn").first
    copy_btn.click()
    expect(copy_btn).to_have_text("Copied!")
    page.wait_for_timeout(1400)
    expect(copy_btn).to_have_text("Copy")


# ── Form validation ───────────────────────────────────────────────────────────


def test_odd_length_hex_shows_error(page: Page, flask_server):
    """Hex with an odd number of nibbles is rejected before submission."""
    page.goto(f"{BASE}/tcp")
    page.locator(".hex-input").fill("aab")  # 3 nibbles — invalid
    page.locator("input[type=button][value='Generate pcap']").click()
    expect(page.locator("#tcphex_error")).not_to_have_text("")


# ── PCAP download ─────────────────────────────────────────────────────────────


def test_tcp_download(page: Page, flask_server):
    page.goto(f"{BASE}/tcp")
    page.locator(".hex-input").fill("48454c4c4f")  # "HELLO"
    with page.expect_download() as dl:
        page.locator("input[type=button][value='Generate pcap']").click()
    assert dl.value.suggested_filename.endswith(".pcap")


@pytest.mark.parametrize("route", ["/udp", "/ip", "/ethernet"])
def test_protocol_download(page: Page, flask_server, route):
    page.goto(f"{BASE}{route}")
    page.locator(".hex-input").fill("48454c4c4f")
    with page.expect_download() as dl:
        page.locator("input[type=button][value='Generate pcap']").click()
    assert dl.value.suggested_filename.endswith(".pcap")
