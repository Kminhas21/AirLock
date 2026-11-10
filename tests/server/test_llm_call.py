import asyncio

import httpx2
import openai
import pytest

from llm_call import LLMUnavailable, create_completion

REQ = httpx2.Request("POST", "https://example.test/v1/chat/completions")


def _resp(status):
    return httpx2.Response(status, request=REQ)


def status_err(cls, status):
    return cls("boom", response=_resp(status), body=None)


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.chat = self
        self.completions = self

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class Sleeper:
    def __init__(self):
        self.delays = []

    async def __call__(self, d):
        self.delays.append(d)


def run(client, sleeper=None, **kw):
    sleeper = sleeper or Sleeper()
    kw.setdefault("rand", lambda: 0.5)
    return asyncio.run(create_completion(client, sleep=sleeper, **kw)), sleeper


def test_success_first_try_forwards_timeout_and_kwargs():
    c = FakeClient(["ok"])
    res, s = run(c, timeout=12.5, model="m", messages=[1])
    assert res == "ok"
    assert c.calls == [{"timeout": 12.5, "model": "m", "messages": [1]}]
    assert s.delays == []


def test_default_timeout_is_60():
    c = FakeClient(["ok"])
    run(c, model="m")
    assert c.calls[0]["timeout"] == 60.0


RETRYABLE = [
    lambda: asyncio.TimeoutError(),
    lambda: openai.APIConnectionError(request=REQ),
    lambda: openai.APITimeoutError(REQ),
    lambda: status_err(openai.RateLimitError, 429),
    lambda: status_err(openai.InternalServerError, 500),
]


@pytest.mark.parametrize("mk", RETRYABLE)
def test_retryable_then_success(mk):
    c = FakeClient([mk(), "ok"])
    res, s = run(c, model="m")
    assert res == "ok"
    assert len(c.calls) == 2
    assert len(s.delays) == 1


def test_backoff_delays_full_jitter():
    c = FakeClient([asyncio.TimeoutError(), asyncio.TimeoutError(), "ok"])
    res, s = run(c, base_delay=1.0, rand=lambda: 0.5)
    assert res == "ok"
    assert s.delays == [0.5 * 1.0 * 1, 0.5 * 1.0 * 2]


def test_backoff_uses_base_delay_and_rand():
    c = FakeClient([asyncio.TimeoutError(), asyncio.TimeoutError(), "ok"])
    _, s = run(c, base_delay=4.0, rand=lambda: 1.0)
    assert s.delays == [4.0, 8.0]


def test_exhaustion_raises_llm_unavailable_with_cause_and_attempts():
    last = status_err(openai.RateLimitError, 429)
    c = FakeClient([asyncio.TimeoutError(), asyncio.TimeoutError(), last])
    s = Sleeper()
    with pytest.raises(LLMUnavailable) as ei:
        asyncio.run(create_completion(c, sleep=s, rand=lambda: 0.5, retries=2))
    assert ei.value.attempts == 3
    assert ei.value.__cause__ is last
    assert len(c.calls) == 3
    assert len(s.delays) == 2  # no sleep after the final failure


def test_retries_zero_means_single_attempt():
    c = FakeClient([asyncio.TimeoutError()])
    s = Sleeper()
    with pytest.raises(LLMUnavailable) as ei:
        asyncio.run(create_completion(c, sleep=s, retries=0))
    assert ei.value.attempts == 1
    assert s.delays == []


@pytest.mark.parametrize(
    "err",
    [
        status_err(openai.AuthenticationError, 401),
        status_err(openai.BadRequestError, 400),
        status_err(openai.NotFoundError, 404),
    ],
)
def test_non_retryable_raises_immediately(err):
    c = FakeClient([err, "ok"])
    s = Sleeper()
    with pytest.raises(type(err)) as ei:
        asyncio.run(create_completion(c, sleep=s, rand=lambda: 0.5))
    assert ei.value is err
    assert len(c.calls) == 1
    assert s.delays == []


def test_llm_unavailable_is_exception():
    assert issubclass(LLMUnavailable, Exception)
