"""Exponential-backoff retry helpers for network operations."""

from __future__ import annotations

import functools
import logging
import random
import time
from typing import Callable, TypeVar

T = TypeVar("T")

_default_logger = logging.getLogger(__name__)


def retry_with_backoff(
    fn: Callable[[], T],
    *,
    max_attempts: int = 10,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    jitter: bool = True,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    logger: logging.Logger | None = None,
) -> T:
    """Call ``fn`` with exponential backoff, retrying on the given exceptions.

    Delay doubles after each failure, capped at ``max_delay``. When ``jitter``
    is true a random factor in [0.5, 1.5) is applied to each computed delay to
    avoid thundering-herd reconnects. On final failure the last exception is
    re-raised.
    """
    log = logger or _default_logger
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    delay = initial_delay
    last_exc: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except retry_on as exc:
            last_exc = exc
            if attempt >= max_attempts:
                log.debug(
                    "retry attempt %d/%d failed (%s); giving up",
                    attempt, max_attempts, exc,
                )
                break

            sleep_for = delay
            if jitter:
                sleep_for = delay * random.uniform(0.5, 1.5)
            sleep_for = min(sleep_for, max_delay)

            log.debug(
                "retry attempt %d/%d failed (%s); next delay=%.2fs",
                attempt, max_attempts, exc, sleep_for,
            )
            time.sleep(sleep_for)
            delay = min(delay * 2.0, max_delay)

    assert last_exc is not None
    raise last_exc


def with_backoff(
    *,
    max_attempts: int = 10,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    jitter: bool = True,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    logger: logging.Logger | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator form of :func:`retry_with_backoff`."""

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> T:
            return retry_with_backoff(
                lambda: fn(*args, **kwargs),
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                jitter=jitter,
                retry_on=retry_on,
                logger=logger,
            )

        return wrapper

    return decorator
