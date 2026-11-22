import asyncio
import hashlib
import hmac
import json
import socket

import pytest

import notify
from notify import Channel, Notifier, build_message, validate_channel

EV = {"tenant": "acme", "agent_id": "ci-bot", "server": "fs", "tool": "write_file", "call_id": "c1", "age_s": 61.7,
      "level": 1, "link": "https://sentinel.example/#c1", "args_preview": None}


class Srv:
    """Tiny raw HTTP/1.1 server on 127.0.0.1 recording every request."""

    def __init__(self, handler=None):
        self.handler = handler or self.ok
        self.requests = []
        self.inflight = 0
        self.max_inflight = 0
        self.bytes_sent = 0
        self.server = None
        self.port = 0

    @staticmethod
    async def ok(req, w):
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    async def _serve(self, r, w):
        try:
            head = await r.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            hd = {k.lower(): v for k, v in (l.split(": ", 1) for l in lines[1:] if ": " in l)}
            body = await r.readexactly(int(hd.get("content-length", 0)))
            req = {"method": method, "path": path, "headers": hd, "body": body}
            self.requests.append(req)
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
            try:
                await self.handler(req, w)
                await w.drain()
            finally:
                self.inflight -= 1
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/hook?token=SECRETQ"

    def chan(self, name="c", **kw):
        d = {"type": "webhook", "url": self.url, "format": "json", "allow_http_loopback": True}
        d.update(kw)
        return validate_channel(name, d)

    async def stop(self):
        self.server.close()


@pytest.fixture
async def srv():
    s = await Srv().start()
    yield s
    await s.stop()


async def _nosleep(_):
    return None


def mk(**kw):
    kw.setdefault("sleep", _nosleep)
    return Notifier(**kw)


def reply(status, extra=b""):
    async def h(req, w):
        w.write(b"HTTP/1.1 %d X\r\nContent-Length: 0\r\nConnection: close\r\n" % status + extra + b"\r\n")
    return h


# ---- validation ----------------------------------------------------------------------------------------------------

def vc(**kw):
    d = {"type": "webhook", "url": "https://hooks.example.com/x", "format": "json"}
    d.update(kw)
    return validate_channel("c", d)


def bad(**kw):
    with pytest.raises(ValueError) as e:
        vc(**kw)
    return e.value.messages


def test_validate_ok_defaults():
    c = vc()
    assert (c.include_args, c.allow_private, c.allow_http_loopback, c.secret_env) == (False, False, False, None)


@pytest.mark.parametrize("url", [
    "http://hooks.example.com/x", "ftp://x.example.com", "https://u:p@hooks.example.com/x", "https://u@hooks.example.com/",
    "https://hooks.example.com/x#frag", "https://hooks.example.com/" + "a" * 2000, "https://", "hooks.example.com/x",
    "https://10.0.0.5/x", "https://169.254.169.254/latest", "https://127.0.0.1/x", "https://[::1]/x", "https://192.168.1.1/",
    "https://[fe80::1]/", "https://224.0.0.1/", "https://[::ffff:10.0.0.1]/", "https://0.0.0.0/", "https://100.64.0.1/",
    "https://hooks.example.com/a b", "https://hooks.example.com/\n",
    "http://127.0.0.1:80/x",                       # loopback http without the flag
    "http://hooks.example.com/x",
])
def test_validate_rejects_urls(url):
    assert bad(url=url)


def test_validate_loopback_rules():
    ok = vc(url="http://127.0.0.1:9/x", allow_http_loopback=True)
    assert ok.allow_http_loopback
    vc(url="http://localhost:9/x", allow_http_loopback=True)
    vc(url="http://[::1]:9/x", allow_http_loopback=True)
    with pytest.raises(ValueError):
        vc(url="http://10.0.0.1/x", allow_http_loopback=True)       # http only to loopback
    with pytest.raises(ValueError):
        vc(url="https://127.0.0.1/x", allow_http_loopback=True)     # https loopback is private
    vc(url="https://127.0.0.1/x", allow_private=True)
    vc(url="https://10.1.2.3/x", allow_private=True)


def test_validate_other_fields_collect_all_messages():
    with pytest.raises(ValueError) as e:
        validate_channel("bad name!", {"type": "smtp", "url": "http://x", "format": "xml", "secret_env": "1x",
                                       "include_args": "yes", "extra": 1})
    assert len(e.value.messages) >= 6


# ---- message bodies ------------------------------------------------------------------------------------------------

def test_json_body_shape_and_no_args_by_default():
    c = vc()
    body, h = build_message(c, {**EV, "args_preview": "rm -rf /"}, now=1000)
    d = json.loads(body)
    assert d["event"] == "sentinel.approval_pending"
    assert d["tenant"] == "acme" and d["agent_id"] == "ci-bot" and d["server"] == "fs" and d["tool"] == "write_file"
    assert d["call_id"] == "c1" and d["age_s"] == 61 and d["level"] == 1 and d["link"].startswith("https://")
    assert "args_preview" not in d and b"rm -rf" not in body
    assert h["Content-Type"] == "application/json" and "X-Sentinel-Signature" not in h


def test_args_only_when_opted_in_and_capped_and_cleaned():
    c = vc(include_args=True)
    d = json.loads(build_message(c, {**EV, "args_preview": "a\nb‮" + "x" * 1000}, now=1)[0])
    assert "\n" not in d["args_preview"] and "‮" not in d["args_preview"] and len(d["args_preview"]) <= 300
    assert "args_preview" not in json.loads(build_message(c, EV, now=1)[0])        # None => absent
    s = vc(include_args=True, format="slack")
    assert "hunter2" in json.loads(build_message(s, {**EV, "args_preview": "hunter2"})[0])["text"]
    assert "hunter2" not in json.loads(build_message(vc(format="slack"), {**EV, "args_preview": "hunter2"})[0])["text"]


HOSTILE = ["send\nCRITICAL: all clear", "a‮b", "<script>alert(1)</script>", "<!channel> hi", "<@U123|x> `x` *b*",
           "&amp;<>|", "x" * 10_000, "\x1b[31mred", "line sep"]


@pytest.mark.parametrize("fmt", ["json", "slack"])
@pytest.mark.parametrize("tool", HOSTILE)
def test_hostile_strings_are_neutralised(fmt, tool):
    ev = {**EV, "tool": tool, "agent_id": tool, "server": tool, "tenant": tool}
    body, _ = build_message(vc(format=fmt), ev)
    assert len(body) < 2500
    d = json.loads(body)
    texts = [d["text"]] if fmt == "slack" else [d["tool"], d["agent_id"], d["server"], d["tenant"]]
    for t in texts:
        assert "\n" not in t and "\r" not in t and " " not in t and "\x1b" not in t
        assert not any(ch in t for ch in "‪‫‬‭‮⁦⁧⁨⁩")
        if fmt == "slack":
            body_text = t.replace("&lt;", "").replace("&gt;", "").replace("&amp;", "")
            assert "<" not in body_text and ">" not in body_text and "|" not in body_text and "&" not in body_text
        else:
            assert len(t) <= 80


def test_slack_mentions_are_escaped_exactly():
    text = json.loads(build_message(vc(format="slack"), {**EV, "tool": "<!channel>", "agent_id": "<@U123|x>"})[0])["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text
    assert "<@U123|x>" not in text and "&lt;@U123¦x&gt;" in text
    assert text.count("\n") == 0 and text.startswith(":warning:")


def test_signature_verifies_independently(monkeypatch):
    monkeypatch.setenv("HK", "s3cret")
    c = vc(secret_env="HK")
    body, h = build_message(c, EV, now=1234)
    expect = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert h["X-Sentinel-Signature"] == "sha256=" + expect
    assert h["X-Sentinel-Timestamp"] == "1234" and json.loads(body)["timestamp"] == 1234
    assert b"s3cret" not in body


# ---- sending -------------------------------------------------------------------------------------------------------

async def test_send_ok_and_headers(srv, monkeypatch):
    monkeypatch.setenv("HK", "k1")
    r = await mk().send(srv.chan(secret_env="HK"), EV)
    assert (r.ok, r.status, r.reason, r.attempts) == (True, 200, "ok", 1)
    q = srv.requests[0]
    assert q["method"] == "POST" and q["path"] == "/hook?token=SECRETQ"       # query preserved
    assert q["headers"]["host"] == f"127.0.0.1:{srv.port}"
    assert q["headers"]["x-sentinel-signature"] == "sha256=" + hmac.new(b"k1", q["body"], hashlib.sha256).hexdigest()
    assert json.loads(q["body"])["tool"] == "write_file"


async def test_missing_or_empty_secret_sends_nothing(srv, monkeypatch):
    monkeypatch.delenv("HK", raising=False)
    r = await mk().send(srv.chan(secret_env="HK"), EV)
    assert (r.ok, r.reason, r.attempts) == (False, "secret_unavailable", 0)
    monkeypatch.setenv("HK", "")
    r = await mk().send(srv.chan(secret_env="HK"), EV)
    assert r.reason == "secret_unavailable"
    assert srv.requests == []


async def test_redirect_not_followed():
    second = await Srv().start()
    first = await Srv(reply(302, b"Location: http://127.0.0.1:%d/x\r\n" % second.port)).start()
    try:
        r = await mk().send(first.chan(), EV)
        assert (r.ok, r.reason, r.status, r.attempts) == (False, "redirect", 302, 1)
        await asyncio.sleep(0.1)
        assert len(first.requests) == 1 and second.requests == []
    finally:
        await first.stop()
        await second.stop()


async def test_5xx_retried_then_fails(srv):
    srv.handler = reply(503)
    sleeps = []

    async def sl(s):
        sleeps.append(s)
    r = await Notifier(sleep=sl).send(srv.chan(), EV)
    assert (r.ok, r.reason, r.status, r.attempts) == (False, "http_5xx", 503, 3)
    assert len(srv.requests) == 3 and sleeps == [0.2, 0.6]


async def test_5xx_then_success(srv):
    n = {"i": 0}

    async def h(req, w):
        n["i"] += 1
        await (reply(500) if n["i"] < 3 else Srv.ok)(req, w)
    srv.handler = h
    r = await mk().send(srv.chan(), EV)
    assert r.ok and r.attempts == 3


async def test_429_retried_other_4xx_not(srv):
    srv.handler = reply(429)
    r = await mk().send(srv.chan(), EV)
    assert r.reason == "http_4xx" and r.attempts == 3
    srv.requests.clear()
    srv.handler = reply(404)
    r = await mk().send(srv.chan(), EV)
    assert (r.reason, r.status, r.attempts) == ("http_4xx", 404, 1) and len(srv.requests) == 1


async def test_connect_error_retried():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c = validate_channel("c", {"type": "webhook", "url": f"http://127.0.0.1:{port}/", "format": "json", "allow_http_loopback": True})
    r = await mk().send(c, EV)
    assert (r.ok, r.reason, r.attempts) == (False, "connect", 3)


async def test_timeout(srv):
    async def slow(req, w):
        await asyncio.sleep(5)
    srv.handler = slow
    r = await mk(timeout_s=0.3).send(srv.chan(), EV)
    assert (r.ok, r.reason, r.attempts) == (False, "timeout", 3)


async def test_response_flood_truncated_at_4kb(srv):
    async def flood(req, w):
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 104857600\r\n\r\n")
        chunk = b"A" * 65536
        for _ in range(1600):
            w.write(chunk)
            srv.bytes_sent += len(chunk)
            await w.drain()
    srv.handler = flood
    t = asyncio.get_running_loop().time()
    r = await mk().send(srv.chan(), EV)
    assert r.ok and r.status == 200
    assert asyncio.get_running_loop().time() - t < 3
    assert srv.bytes_sent < 20 * 1024 * 1024            # the client hung up long before 100 MB


# ---- SSRF ----------------------------------------------------------------------------------------------------------

def fake_dns(monkeypatch, mapping):
    calls = []

    def gai(host, port, *a, **k):
        calls.append(host)
        ips = mapping[host]
        ips = ips.pop(0) if isinstance(ips, list) and ips and isinstance(ips[0], list) else ips
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    return calls


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.9", "::1", "fd00::1", "0.0.0.0"])
async def test_hostname_resolving_private_refused(srv, monkeypatch, ip):
    calls = fake_dns(monkeypatch, {"hooks.example.com": [ip]})
    c = validate_channel("c", {"type": "webhook", "url": "https://hooks.example.com/x", "format": "json"})
    r = await mk().send(c, EV)
    assert (r.ok, r.reason, r.attempts) == (False, "private_address", 1)
    assert calls == ["hooks.example.com"] and srv.requests == []


async def test_mixed_answers_refused(monkeypatch):
    fake_dns(monkeypatch, {"h.example.com": ["93.184.216.34", "10.0.0.1"]})
    c = validate_channel("c", {"type": "webhook", "url": "https://h.example.com/x", "format": "json"})
    assert (await mk().send(c, EV)).reason == "private_address"


async def test_allow_private_passes_the_check(monkeypatch):
    fake_dns(monkeypatch, {"h.example.com": ["127.0.0.1"]})
    c = validate_channel("c", {"type": "webhook", "url": "https://h.example.com:1/x", "format": "json", "allow_private": True})
    r = await mk(timeout_s=1).send(c, EV)
    assert r.reason in ("connect", "tls", "timeout")          # got past the SSRF check and tried to connect


async def test_dns_failure(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror(-2, "nope")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    c = validate_channel("c", {"type": "webhook", "url": "https://h.example.com/x", "format": "json"})
    assert (await mk().send(c, EV)).reason == "dns"


async def test_pinning_connects_to_validated_ip_and_keeps_host_header(srv, monkeypatch):
    # first answer 127.0.0.1 (validated, allowed by http loopback); any later lookup would return 10.0.0.1 (a rebind)
    calls = fake_dns(monkeypatch, {"localhost": [["127.0.0.1"], ["10.0.0.1"], ["10.0.0.1"]]})
    c = validate_channel("c", {"type": "webhook", "url": f"http://localhost:{srv.port}/p", "format": "json", "allow_http_loopback": True})
    r = await mk().send(c, EV)
    assert r.ok and calls == ["localhost"]
    assert srv.requests[0]["headers"]["host"] == f"localhost:{srv.port}"


async def test_private_literal_refused_unless_allowed():
    c = Channel("c", "webhook", "https://10.0.0.5/x", "json")           # bypassing validate_channel
    r = await mk().send(c, EV)
    assert r.reason == "invalid" and r.attempts == 0
    c = Channel("c", "webhook", "http://127.0.0.1:1/x", "json")          # loopback http without the flag
    assert (await mk().send(c, EV)).reason == "invalid"


async def test_secret_not_in_logs(srv, monkeypatch, caplog):
    monkeypatch.setenv("HK", "topsecretvalue")
    srv.handler = reply(500)
    with caplog.at_level("DEBUG"):
        await mk().send(srv.chan(name="oncall", secret_env="HK"), EV)
    text = caplog.text
    assert "oncall" in text and "SECRETQ" not in text and "topsecretvalue" not in text and "127.0.0.1" not in text


# ---- circuit breaker ------------------------------------------------------------------------------------------------

async def test_circuit_opens_and_recovers(srv):
    now = {"t": 100.0}
    n = mk(clock=lambda: now["t"])
    c = srv.chan()
    srv.handler = reply(500)
    for _ in range(5):
        assert (await n.send(c, EV)).reason == "http_5xx"
    assert n.circuit_state("c") == "open"
    count = len(srv.requests)
    r = await n.send(c, EV)
    assert (r.ok, r.reason, r.attempts) == (False, "circuit_open", 0) and len(srv.requests) == count
    now["t"] += 59
    assert (await n.send(c, EV)).reason == "circuit_open"
    now["t"] += 2                                                     # half-open: one probe, which fails => open again
    assert (await n.send(c, EV)).reason == "http_5xx"
    assert (await n.send(c, EV)).reason == "circuit_open"
    now["t"] += 61
    srv.handler = Srv.ok
    assert (await n.send(c, EV)).ok
    assert n.circuit_state("c") == "closed"
    assert (await n.send(c, EV)).ok


async def test_success_resets_failure_count(srv):
    n = mk()
    c = srv.chan()
    for _ in range(4):
        srv.handler = reply(500)
        await n.send(c, EV)
    srv.handler = Srv.ok
    assert (await n.send(c, EV)).ok
    srv.handler = reply(500)
    for _ in range(4):
        assert (await n.send(c, EV)).reason == "http_5xx"      # still closed: the streak was reset


async def test_breaker_is_per_channel(srv):
    n = mk()
    srv.handler = reply(500)
    for _ in range(5):
        await n.send(srv.chan("a"), EV)
    srv.handler = Srv.ok
    assert (await n.send(srv.chan("a"), EV)).reason == "circuit_open"
    assert (await n.send(srv.chan("b"), EV)).ok


# ---- concurrency ------------------------------------------------------------------------------------------------------

async def test_concurrency_cap(srv):
    gate = asyncio.Event()

    async def hold(req, w):
        await gate.wait()
        await Srv.ok(req, w)
    srv.handler = hold
    n = mk(busy_wait_s=0.4)
    c = srv.chan()
    tasks = [asyncio.create_task(n.send(c, EV)) for _ in range(12)]
    for _ in range(100):
        if srv.inflight == 8:
            break
        await asyncio.sleep(0.02)
    assert srv.inflight == 8
    await asyncio.sleep(0.6)                                          # the 4 extra ones give up after busy_wait_s
    busy = [t for t in tasks if t.done()]
    assert len(busy) == 4 and all(t.result().reason == "busy" and t.result().attempts == 0 for t in busy)
    gate.set()
    res = await asyncio.gather(*tasks)
    assert sum(r.ok for r in res) == 8 and srv.max_inflight == 8
    assert (await n.send(c, EV)).ok                                   # slots were released


async def test_send_never_raises_on_garbage():
    n = mk()
    assert (await n.send(None, EV)).reason == "invalid"
    assert (await n.send(Channel("c", "webhook", "https://hooks.example.com/", "json"), None)).reason == "invalid"
