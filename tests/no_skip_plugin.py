"""pytest plugin: with SENTINEL_NO_SKIP=1, a skipped or xfail test is a FAILURE (docs/TESTING_REALITY.md, "live tests actually happen").

The reality gate stages load it with `-p tests.no_skip_plugin` and set SENTINEL_NO_SKIP=1, so a missing server, CLI or model can never turn a
live stage green by skipping. A plain module on purpose, not a conftest.py (a second conftest shadows `from conftest import` in older suites).
An xfail (marker or imperative pytest.xfail) and an unexpected pass of one fail too: either way the live test did not prove what it claims.
Nothing collected is already exit code 5, which verify.sh's run() counts as a failure."""
import os

import pytest

_REASON = "SENTINEL_NO_SKIP=1: a skipped or xfail test is a failure in this stage"


def _on() -> bool:
    return os.environ.get("SENTINEL_NO_SKIP") == "1"


def _why(rep) -> str:
    lr = rep.longrepr
    if isinstance(lr, tuple) and len(lr) == 3:         # (path, line, "Skipped: reason")
        return str(lr[2])
    return str(lr)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if not _on():
        return
    if hasattr(rep, "wasxfail"):                         # xfailed (reported as skipped) or xpassed (reported as passed)
        rep.outcome = "failed"
        rep.longrepr = f"{_REASON} ({rep.when}): xfail: {rep.wasxfail or 'no reason'}"
        del rep.wasxfail
    elif rep.skipped:
        rep.outcome = "failed"
        rep.longrepr = f"{_REASON} ({rep.when}): {_why(rep)}"


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector):
    outcome = yield
    rep = outcome.get_result()
    if _on() and rep.skipped:                            # pytest.skip(allow_module_level=True), importorskip
        rep.outcome = "failed"
        rep.longrepr = f"{_REASON} (collection of {collector.nodeid}): {_why(rep)}"


def pytest_report_header(config):
    return "SENTINEL_NO_SKIP=1: skips and xfails are failures" if _on() else None
