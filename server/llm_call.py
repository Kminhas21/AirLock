"""Resilient wrapper around chat.completions.create (bug B5)."""

import asyncio
import random

import openai

RETRYABLE = (
    asyncio.TimeoutError,
    openai.APIConnectionError,  # APITimeoutError subclasses this; listed below for clarity
    openai.APITimeoutError,
    openai.RateLimitError,
    openai.InternalServerError,
)


class LLMUnavailable(Exception):
    """Raised when the LLM call still fails after all retries."""

    def __init__(self, message: str, attempts: int):
        super().__init__(message)
        self.attempts = attempts


async def create_completion(
    client,
    *,
    timeout=60.0,
    retries=2,
    base_delay=1.0,
    sleep=asyncio.sleep,
    rand=random.random,
    **kwargs,
):
    attempts = 0
    while True:
        attempts += 1
        try:
            return await client.chat.completions.create(timeout=timeout, **kwargs)
        except RETRYABLE as exc:
            if attempts > retries:
                raise LLMUnavailable(
                    f"LLM unavailable after {attempts} attempt(s): {exc!r}", attempts
                ) from exc
            await sleep(rand() * base_delay * 2 ** (attempts - 1))
