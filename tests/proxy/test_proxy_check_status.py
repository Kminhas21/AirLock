"""Proxy._check_status (sentinel_proxy/proxy.py): the startup proof that a sandboxed downstream really runs sandboxed. A `require`d sandbox that
reported no status line, or a missing layer, is refused (SandboxRefused: the proxy does not start); an optional one is tolerated, and an
unsandboxed server has nothing to check. No processes: the tap is a stand-in with a `status`."""
import sys
from types import SimpleNamespace

import pytest

from sentinel_proxy.config import parse_config
from sentinel_proxy.proxy import Proxy, SandboxRefused

FAIL = "unused.py"


class Link:
    async def decide(self, frame):
        raise AssertionError("no call is made")

def _proxy(require=True, sandboxed=True):
    c = parse_config({"servers": {"fs": {"command": sys.executable, "args": [FAIL],
                                         **({"sandbox": {"read": [], "network": "none", "require": require}} if sandboxed else {})}}})
    return Proxy(c, Link()), c.servers["fs"]


def test_check_status_refuses_a_required_sandbox_that_reported_nothing():
    p, sc = _proxy()
    with pytest.raises(SandboxRefused, match="reported no status"):
        p._check_status(sc, SimpleNamespace(status=None))


def test_check_status_refuses_a_required_sandbox_with_a_missing_layer_and_names_it():
    p, sc = _proxy()
    with pytest.raises(SandboxRefused, match="landlock_fs, netns"):
        p._check_status(sc, SimpleNamespace(status={"missing": ["landlock_fs", "netns"], "layers": ["env"]}))


def test_check_status_tolerates_what_an_optional_or_absent_sandbox_reports():
    p, sc = _proxy(require=False)
    p._check_status(sc, SimpleNamespace(status=None))
    p._check_status(sc, SimpleNamespace(status={"missing": ["netns"]}))
    p2, sc2 = _proxy(sandboxed=False)
    p2._check_status(sc2, SimpleNamespace(status=None))
    p3, sc3 = _proxy()
    p3._check_status(sc3, SimpleNamespace(status={"missing": [], "layers": ["env", "landlock_fs"]}))     # a complete status passes


