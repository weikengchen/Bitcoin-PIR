"""
Async WebSocket client for PIR servers.

Uses the `websockets` library for async WebSocket connections.
Supports FIFO response matching, ping/pong heartbeat, and reconnection.
"""

from __future__ import annotations

import asyncio
import struct
import logging
from collections import deque
from typing import Optional

import websockets
from websockets.asyncio.client import connect as ws_connect

from .pir_protocol import encode_ping, is_pong

logger = logging.getLogger(__name__)


class PirConnection:
    """Async WebSocket connection to a single PIR server."""

    def __init__(self, url: str, timeout: float = 120.0):
        self.url = url
        self.timeout = timeout
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._pending: deque[asyncio.Future] = deque()
        self._reader_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        """Connect to the WebSocket server."""
        self._ws = await ws_connect(
            self.url,
            max_size=50 * 1024 * 1024,  # 50 MB max message size
            ping_interval=None,  # We handle heartbeat ourselves
            ping_timeout=None,
        )
        self._pending = deque()
        self._reader_task = asyncio.create_task(self._reader_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info(f'Connected to {self.url}')

    async def close(self) -> None:
        """Close the connection."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
        if self._reader_task:
            self._reader_task.cancel()
            self._reader_task = None
        if self._ws:
            await self._ws.close()
            self._ws = None
        # Cancel any pending futures
        while self._pending:
            fut = self._pending.popleft()
            if not fut.done():
                fut.cancel()

    @property
    def is_connected(self) -> bool:
        return self._ws is not None and self._ws.state.name == 'OPEN'

    async def send_request(self, data: bytes) -> bytes:
        """Send a binary request and wait for the FIFO-matched response."""
        if not self._ws:
            raise ConnectionError(f'Not connected to {self.url}')

        loop = asyncio.get_event_loop()
        fut: asyncio.Future[bytes] = loop.create_future()
        self._pending.append(fut)

        await self._ws.send(data)

        try:
            return await asyncio.wait_for(fut, timeout=self.timeout)
        except asyncio.TimeoutError:
            # Remove from pending if still there
            try:
                self._pending.remove(fut)
            except ValueError:
                pass
            raise TimeoutError(f'Request to {self.url} timed out')

    async def _reader_loop(self) -> None:
        """Background task that reads messages and resolves pending futures."""
        try:
            async for message in self._ws:
                if isinstance(message, str):
                    continue  # Ignore text messages

                raw = bytes(message)

                # Skip Pong responses (heartbeat replies)
                if is_pong(raw):
                    continue

                # Resolve the next pending future (FIFO order)
                if self._pending:
                    fut = self._pending.popleft()
                    if not fut.done():
                        fut.set_result(raw)
                else:
                    logger.warning(f'Received unexpected message from {self.url}')
        except websockets.ConnectionClosed:
            logger.info(f'Connection closed: {self.url}')
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f'Reader error for {self.url}: {e}')
        finally:
            # Cancel remaining pending futures
            while self._pending:
                fut = self._pending.popleft()
                if not fut.done():
                    fut.set_exception(ConnectionError(f'Connection to {self.url} lost'))

    async def _heartbeat_loop(self) -> None:
        """Send periodic Ping to keep the connection alive."""
        try:
            while True:
                await asyncio.sleep(30)
                if self._ws and self.is_connected:
                    ping_msg = encode_ping()
                    await self._ws.send(ping_msg)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f'Heartbeat error for {self.url}: {e}')
