"""OCTET STRING normalisation: textual values must not degrade to hex."""

from __future__ import annotations

from pysnmp.hlapi.v3arch.asyncio import ObjectIdentifier, OctetString

from snmp_test.snmp.transport import _octet_string_text, _to_varbind

OID = "1.3.6.1.4.1.52305.1.6.0"


def test_newline_text_octet_string_is_decoded():
    raw = b"0.03.0000\n (Nov 13 2026\n 13:17:39 CST\n)"
    vb = _to_varbind((ObjectIdentifier(OID), OctetString(raw)))
    assert vb.oid == OID and vb.type == "OctetString"
    assert vb.value == raw.decode("utf-8")
    assert not vb.value.startswith("0x")


def test_plain_text_octet_string_is_decoded():
    vb = _to_varbind((ObjectIdentifier(OID), OctetString(b"Mock BMC SNMP Agent")))
    assert vb.value == "Mock BMC SNMP Agent"


def test_binary_octet_string_stays_hex():
    vb = _to_varbind((ObjectIdentifier(OID), OctetString(bytes([0x00, 0x01, 0xFF]))))
    assert vb.value == "0x0001ff"


def test_non_utf8_octet_string_stays_hex():
    vb = _to_varbind((ObjectIdentifier(OID), OctetString(b"\xff\xfe\x80")))
    assert vb.value == "0xfffe80"


def test_octet_string_text_helper():
    assert _octet_string_text(OctetString(b"Nov 13 2026\n 13:17:39 CST\n")) == (
        "Nov 13 2026\n 13:17:39 CST\n"
    )
    assert _octet_string_text(OctetString(b"")) == ""
