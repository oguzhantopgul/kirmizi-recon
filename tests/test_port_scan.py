import pytest

from kirmizi_recon.tools.infra import (
    WEB_PORTS,
    _expand_spec,
    _normalize_ports,
    _parse_nmap_xml,
    port_scan,
)


def test_port_scan_rejects_non_ip():
    # Defense-in-depth: only a resolved IP may reach nmap's argv.
    out = port_scan("acme.example.com; rm -rf /")
    assert "error" in out and "resolved IP" in out["error"]
    out2 = port_scan("--script=vuln")
    assert "error" in out2

_SAMPLE_XML = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_normalize_ports_keywords_and_specs():
    assert _normalize_ports("") == ("top", 100)
    assert _normalize_ports("top-100") == ("top", 100)
    assert _normalize_ports("top-1000") == ("top", 1000)
    assert _normalize_ports("web") == ("list", WEB_PORTS)
    assert _normalize_ports("22,80,443") == ("spec", "22,80,443")
    assert _normalize_ports("1-1024") == ("spec", "1-1024")


@pytest.mark.parametrize("bad", ["80; rm -rf /", "--script=vuln", "80 443", "abc", "-oN x"])
def test_normalize_ports_rejects_injection(bad):
    with pytest.raises(ValueError):
        _normalize_ports(bad)


def test_expand_spec_ranges_and_cap():
    assert _expand_spec("22,80-82") == [22, 80, 81, 82]
    # Out-of-range and huge ranges are filtered/capped.
    expanded = _expand_spec("1-70000")
    assert len(expanded) <= 2048
    assert all(0 < p <= 65535 for p in expanded)


def test_parse_nmap_xml_open_only_with_service():
    ports = _parse_nmap_xml(_SAMPLE_XML)
    assert [p["port"] for p in ports] == [22, 443]  # closed 80 excluded, sorted
    ssh = ports[0]
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.9p1"


def test_parse_nmap_xml_empty():
    assert _parse_nmap_xml(b"") == []
