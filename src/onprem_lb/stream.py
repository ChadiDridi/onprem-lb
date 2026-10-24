"""Bidirectional byte pumping with half-close and an idle timeout."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

CHUNK = 64 * 1024


async def splice(
    a_reader: asyncio.StreamReader,
    a_writer: asyncio.StreamWriter,
    b_reader: asyncio.StreamReader,
    b_writer: asyncio.StreamWriter,
    idle: float,
    count: Callable[[str, int], None] | None = None,
) -> None:
    """Copy a->b and b->a until both sides finish or nothing moves for
    ``idle`` seconds. EOF on one side is propagated as a half-close when the
    other transport supports it (plain TCP); otherwise the connection ends."""
    loop = asyncio.get_running_loop()
    last = [loop.time()]

    async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, direction: str) -> bool:
        """Returns True if the half-close was propagated."""
        while True:
            data = await src.read(CHUNK)
            if not data:
                break
            last[0] = loop.time()
            dst.write(data)
            await dst.drain()
            if count:
                count(direction, len(data))
        if dst.can_write_eof():
            try:
                dst.write_eof()
                return True
            except (OSError, RuntimeError):
                return False
        return False

    up = asyncio.create_task(pump(a_reader, b_writer, "in"))
    down = asyncio.create_task(pump(b_reader, a_writer, "out"))
    pending = {up, down}
    try:
        while pending:
            done, pending = await asyncio.wait(pending, timeout=min(idle, 5.0), return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                if t.cancelled() or t.exception() is not None or not t.result():
                    return  # error, or the far side cannot be half-closed
            if not done and loop.time() - last[0] >= idle:
                return
    finally:
        for t in (up, down):
            t.cancel()
        await asyncio.gather(up, down, return_exceptions=True)


def close(*writers: asyncio.StreamWriter | None, abort: bool = False) -> None:
    """Close writers; abort=True resets the connections (used when draining)."""
    for w in writers:
        if w is None:
            continue
        try:
            if abort:
                w.transport.abort()
            else:
                w.close()
        except Exception:  # noqa: BLE001 - closing must never raise
            pass
