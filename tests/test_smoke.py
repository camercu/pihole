"""Unit tests for the pure DNS-packet helpers in pihole_smoke.py."""
import struct

import pihole_smoke as s
import pytest


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


def test_build_query_rejects_an_empty_label():
    # A domain with an empty label ("a..b", trailing dot) would encode a
    # zero-length label mid-name, silently truncating the query. Reject it.
    with pytest.raises(ValueError):
        s.build_query("a..b")


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


def test_parse_response_returns_addresses_for_a_valid_packet():
    assert s.parse_response(_response("a.com", "1.2.3.4")) == ["1.2.3.4"]


def test_parse_response_returns_none_for_a_truncated_packet():
    # A garbled/short datagram must not crash the smoke run; it means
    # "no usable answer", distinct from an empty answer section.
    assert s.parse_response(b"\x12\x34\x81\x80\x00") is None


def test_classify_resolve_true_only_for_a_real_address():
    assert s.classify_resolve(["1.2.3.4"]) is True
    assert s.classify_resolve(["1.2.3.4", "0.0.0.0"]) is True


def test_classify_resolve_false_for_no_answer_sinkhole_or_no_response():
    assert s.classify_resolve([]) is False          # empty answer
    assert s.classify_resolve(["0.0.0.0"]) is False  # sinkholed
    assert s.classify_resolve(None) is False         # resolver gave no response


def test_classify_blocked_true_for_sinkhole_or_empty_answer():
    # Pi-hole blocks via 0.0.0.0 (NULL mode) or an empty answer (NXDOMAIN mode).
    assert s.classify_blocked(["0.0.0.0"]) is True
    assert s.classify_blocked([]) is True


def test_classify_blocked_false_when_resolver_gave_no_response():
    # None = timeout/socket error. A dead resolver must not read as "blocked".
    assert s.classify_blocked(None) is False


def test_classify_blocked_false_for_a_real_address():
    assert s.classify_blocked(["93.184.216.34"]) is False


def test_api_returns_none_status_when_the_endpoint_is_unreachable(monkeypatch):
    # A down FTL API (URLError) must not crash the smoke run with a traceback;
    # _api reports it as "no status" so the caller can emit a FAIL line.
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert s._api("GET", "/dns/blocking") == (None, {})


def test_login_returns_none_when_the_api_is_unreachable(monkeypatch):
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(s, "PW", "secret")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert s.login() is None


def test_login_returns_none_on_an_unexpected_response_body(monkeypatch):
    # Wrong password / unexpected shape: no session in the body => no sid,
    # not a KeyError that aborts before any check prints.
    monkeypatch.setattr(s, "PW", "secret")
    monkeypatch.setattr(s, "_api", lambda *a, **k: (200, {}))
    assert s.login() is None


def test_dns_query_returns_none_on_a_socket_error(monkeypatch):
    # A resolver that can't even be reached (socket error) is "no response",
    # not an empty answer — so it can never read as blocked. Mirrors _api.
    class FakeSock:
        def settimeout(self, _):
            pass

        def sendto(self, *a):
            raise OSError("network is unreachable")

        def close(self):
            pass

    monkeypatch.setattr(s.socket, "socket", lambda *a, **k: FakeSock())
    assert s.dns_query("127.0.0.1", 53, "example.com") is None


def test_main_reports_a_failed_login_as_a_named_failing_check(monkeypatch, capsys):
    # A configured-but-unusable password (login -> None) must surface as an
    # explicit FAIL line and a non-zero exit, not a cryptic "blocking (got None)".
    monkeypatch.setattr(s, "PW", "secret")
    monkeypatch.setattr(s, "login", lambda: None)
    monkeypatch.setattr(s, "_api", lambda *a, **k: (None, {}))
    monkeypatch.setattr(s, "dns_query", lambda *a, **k: None)  # no real sockets

    with pytest.raises(SystemExit) as exc:
        s.main()

    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "[FAIL] API login (failed" in out


def test_is_blocked_empty_answer_is_blocked():
    assert s.is_blocked([]) is True


def test_is_blocked_all_zero_address_is_blocked():
    assert s.is_blocked(["0.0.0.0"]) is True


def test_is_blocked_real_address_is_not_blocked():
    assert s.is_blocked(["93.184.216.34"]) is False
    assert s.is_blocked(["0.0.0.0", "93.184.216.34"]) is False


def test_resolve_password_reads_from_file(tmp_path):
    f = tmp_path / "pw"
    f.write_text("s3cret\n", encoding="utf-8")  # trailing newline from Ansible
    assert s.resolve_password({"PIHOLE_PASSWORD_FILE": str(f)}) == "s3cret"


def test_resolve_password_file_wins_over_inline(tmp_path):
    f = tmp_path / "pw"
    f.write_text("from-file", encoding="utf-8")
    env = {"PIHOLE_PASSWORD_FILE": str(f), "PIHOLE_PASSWORD": "from-env"}
    assert s.resolve_password(env) == "from-file"


def test_resolve_password_falls_back_to_inline_env():
    assert s.resolve_password({"PIHOLE_PASSWORD": "plain"}) == "plain"


def test_resolve_password_empty_file_path_is_ignored():
    env = {"PIHOLE_PASSWORD_FILE": "", "PIHOLE_PASSWORD": "plain"}
    assert s.resolve_password(env) == "plain"


def test_resolve_password_empty_when_unset():
    assert s.resolve_password({}) == ""
