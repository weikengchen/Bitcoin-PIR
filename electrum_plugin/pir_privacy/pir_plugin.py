"""
PIR Privacy Plugin for Electrum.

Replaces Electrum's privacy-leaking server queries with PIR-based UTXO lookups.
The server never learns which addresses the user owns.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.util import log_exceptions

from .pir_constants import DEFAULT_SERVER0_URL, DEFAULT_SERVER1_URL
from .pir_client import BatchPirClient
from .pir_harmony_client import HarmonyPirClient
from .pir_onionpir_client import OnionPirClient
from .pir_synchronizer import PirSynchronizer

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet

logger = logging.getLogger(__name__)


class PirPrivacyPlugin(BasePlugin):
    """
    Main plugin class. Manages PIR client lifecycle and wallet synchronizers.
    """

    def __init__(self, parent, config: 'SimpleConfig', name: str):
        super().__init__(parent, config, name)

        # PIR configuration
        self.pir_protocol = self.config.get('pir_protocol', 'dpf')  # dpf, harmony, onionpir
        self.server0_url = self.config.get('pir_server0_url', DEFAULT_SERVER0_URL)
        self.server1_url = self.config.get('pir_server1_url', DEFAULT_SERVER1_URL)
        self.sync_interval = self.config.get('pir_sync_interval', 30)  # seconds

        # PIR client (shared across wallets)
        self._pir_client: Optional[BatchPirClient] = None

        # Active synchronizers per wallet
        self._synchronizers: dict[str, PirSynchronizer] = {}

        logger.info(f'PIR Privacy plugin initialized (protocol={self.pir_protocol})')

    def _create_pir_client(self):
        """Create a PIR client based on configured protocol."""
        if self.pir_protocol == 'dpf':
            return BatchPirClient(self.server0_url, self.server1_url)
        elif self.pir_protocol == 'harmony':
            return HarmonyPirClient(self.server0_url, self.server1_url)
        elif self.pir_protocol == 'onionpir':
            return OnionPirClient(self.server0_url)
        else:
            logger.warning(f'Unknown protocol {self.pir_protocol}, falling back to DPF')
            return BatchPirClient(self.server0_url, self.server1_url)

    async def _ensure_connected(self) -> BatchPirClient:
        """Ensure PIR client is connected. Creates and connects if needed."""
        if self._pir_client is None or not self._pir_client.is_connected:
            self._pir_client = self._create_pir_client()
            await self._pir_client.connect()
            logger.info('PIR client connected')
        return self._pir_client

    # ── Plugin lifecycle ───────────────────────────────────────────────────

    def on_close(self):
        """Cleanup on plugin shutdown."""
        # Stop all synchronizers
        for wallet_id, sync in self._synchronizers.items():
            sync.stop()
            logger.info(f'Stopped PIR sync for wallet {wallet_id}')
        self._synchronizers.clear()

        # Disconnect PIR client
        if self._pir_client:
            # Schedule disconnect in the event loop
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._pir_client.disconnect())
                else:
                    loop.run_until_complete(self._pir_client.disconnect())
            except Exception:
                pass
            self._pir_client = None

        logger.info('PIR Privacy plugin closed')

    def requires_settings(self) -> bool:
        return True

    # ── Wallet hooks ───────────────────────────────────────────────────────

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window=None):
        """Called when a wallet is opened. Start PIR synchronization."""
        wallet_id = wallet.get_fingerprint()
        if wallet_id in self._synchronizers:
            return  # Already syncing

        logger.info(f'Starting PIR sync for wallet {wallet_id}')

        sync = PirSynchronizer(
            wallet=wallet,
            plugin=self,
            sync_interval=self.sync_interval,
        )
        self._synchronizers[wallet_id] = sync

        # Start sync in background
        network = wallet.network
        if network:
            asyncio.ensure_future(self._start_sync(sync))

    @hook
    def close_wallet(self, wallet: 'Abstract_Wallet'):
        """Called when a wallet is closed. Stop PIR synchronization."""
        wallet_id = wallet.get_fingerprint()
        sync = self._synchronizers.pop(wallet_id, None)
        if sync:
            sync.stop()
            logger.info(f'Stopped PIR sync for wallet {wallet_id}')

    @log_exceptions
    async def _start_sync(self, sync: PirSynchronizer):
        """Start PIR synchronization for a wallet."""
        try:
            pir_client = await self._ensure_connected()
            await sync.start(pir_client)
        except Exception as e:
            logger.error(f'Failed to start PIR sync: {e}')

    # ── Settings ───────────────────────────────────────────────────────────

    def get_settings(self) -> dict:
        """Return current settings for the UI."""
        return {
            'protocol': self.pir_protocol,
            'server0_url': self.server0_url,
            'server1_url': self.server1_url,
            'sync_interval': self.sync_interval,
        }

    def update_settings(self, settings: dict):
        """Update settings from the UI."""
        if 'protocol' in settings:
            self.pir_protocol = settings['protocol']
            self.config.set_key('pir_protocol', self.pir_protocol)

        if 'server0_url' in settings:
            self.server0_url = settings['server0_url']
            self.config.set_key('pir_server0_url', self.server0_url)

        if 'server1_url' in settings:
            self.server1_url = settings['server1_url']
            self.config.set_key('pir_server1_url', self.server1_url)

        if 'sync_interval' in settings:
            self.sync_interval = settings['sync_interval']
            self.config.set_key('pir_sync_interval', self.sync_interval)

        # Reconnect with new settings if needed
        if self._pir_client:
            asyncio.ensure_future(self._reconnect())

    @log_exceptions
    async def _reconnect(self):
        """Reconnect PIR client after settings change."""
        if self._pir_client:
            await self._pir_client.disconnect()
            self._pir_client = None
        await self._ensure_connected()

        # Restart all synchronizers
        for sync in self._synchronizers.values():
            await sync.start(self._pir_client)
