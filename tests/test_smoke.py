"""Unit tests for the pure DNS-packet helpers in pihole_smoke.py."""
import struct

import pihole_smoke as s


def test_build_query_encodes_name_and_asks_for_an_a_record():
    q = s.build_query("a.com", qid=0x1234)
    qid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", q[:12])
    assert qid == 0x1234
    assert flags & 0x0100  # recursion desired
    assert qd == 1
    assert an == 0
    # name is length-prefixed labels ending in a root octet, then QTYPE/QCLASS
    assert q[12:19] == b"\x01a\x03com\x00"
    assert struct.unpack(">HH", q[19:23]) == (1, 1)  # A / IN


def _response(name, ip, qid=0x1234):
    """A minimal well-formed A-record response, built independently of the parser."""
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    question = labels + struct.pack(">HH", 1, 1)
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4)
              + bytes(int(o) for o in ip.split(".")))
    return header + question + answer


def test_parse_answers_extracts_the_a_record_address():
    assert s.parse_answers(_response("a.com", "1.2.3.4")) == ["1.2.3.4"]


def test_parse_answers_no_answer_section_yields_empty():
    header = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0)
    labels = b"\x01a\x03com\x00" + struct.pack(">HH", 1, 1)
    assert s.parse_answers(header + labels) == []


def test_is_blocked_empty_answer_is_blocked():
    assert s.is_blocked([]) is True


def test_is_blocked_all_zero_address_is_blocked():
    assert s.is_blocked(["0.0.0.0"]) is True


def test_is_blocked_real_address_is_not_blocked():
    assert s.is_blocked(["93.184.216.34"]) is False
    assert s.is_blocked(["0.0.0.0", "93.184.216.34"]) is False
