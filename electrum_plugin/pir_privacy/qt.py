"""
Qt GUI for PIR Privacy plugin — settings dialog and status display.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QComboBox, QSpinBox, QPushButton,
    QGroupBox, QFrame,
)
from PyQt5.QtCore import Qt

from electrum.i18n import _
from electrum.gui.qt.util import WindowModalDialog, Buttons, OkButton, CancelButton

from .pir_plugin import PirPrivacyPlugin

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow


class Plugin(PirPrivacyPlugin):
    """Qt-specific plugin class with settings UI."""

    def requires_settings(self) -> bool:
        return True

    def settings_widget(self, window: 'ElectrumWindow') -> QWidget:
        """Return settings widget for the plugin settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # ── Protocol selection ─────────────────────────────────────────
        protocol_group = QGroupBox(_('PIR Protocol'))
        protocol_layout = QGridLayout()

        protocol_layout.addWidget(QLabel(_('Protocol:')), 0, 0)
        self._protocol_combo = QComboBox()
        self._protocol_combo.addItems([
            'DPF 2-Server (recommended)',
            'HarmonyPIR 2-Server',
            'OnionPIRv2 1-Server',
        ])
        protocol_map = {'dpf': 0, 'harmony': 1, 'onionpir': 2}
        self._protocol_combo.setCurrentIndex(protocol_map.get(self.pir_protocol, 0))
        protocol_layout.addWidget(self._protocol_combo, 0, 1)

        protocol_group.setLayout(protocol_layout)
        layout.addWidget(protocol_group)

        # ── Server URLs ────────────────────────────────────────────────
        server_group = QGroupBox(_('Server Configuration'))
        server_layout = QGridLayout()

        server_layout.addWidget(QLabel(_('Server 0 URL:')), 0, 0)
        self._server0_input = QLineEdit(self.server0_url)
        self._server0_input.setPlaceholderText('wss://dpf1.example.com')
        server_layout.addWidget(self._server0_input, 0, 1)

        server_layout.addWidget(QLabel(_('Server 1 URL:')), 1, 0)
        self._server1_input = QLineEdit(self.server1_url)
        self._server1_input.setPlaceholderText('wss://dpf2.example.com')
        server_layout.addWidget(self._server1_input, 1, 1)

        server_group.setLayout(server_layout)
        layout.addWidget(server_group)

        # ── Sync settings ──────────────────────────────────────────────
        sync_group = QGroupBox(_('Synchronization'))
        sync_layout = QGridLayout()

        sync_layout.addWidget(QLabel(_('Poll interval (seconds):')), 0, 0)
        self._interval_spin = QSpinBox()
        self._interval_spin.setRange(5, 300)
        self._interval_spin.setValue(self.sync_interval)
        sync_layout.addWidget(self._interval_spin, 0, 1)

        sync_group.setLayout(sync_layout)
        layout.addWidget(sync_group)

        # ── Status display ─────────────────────────────────────────────
        status_group = QGroupBox(_('Status'))
        status_layout = QVBoxLayout()
        self._status_label = QLabel(_('Not synced yet'))
        self._status_label.setWordWrap(True)
        status_layout.addWidget(self._status_label)

        refresh_btn = QPushButton(_('Refresh Status'))
        refresh_btn.clicked.connect(self._update_status_display)
        status_layout.addWidget(refresh_btn)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        # ── Apply button ───────────────────────────────────────────────
        apply_btn = QPushButton(_('Apply Settings'))
        apply_btn.clicked.connect(self._apply_settings)
        layout.addWidget(apply_btn)

        layout.addStretch()
        self._update_status_display()
        return widget

    def _apply_settings(self):
        """Apply settings from the UI inputs."""
        protocol_idx = self._protocol_combo.currentIndex()
        protocol_map = {0: 'dpf', 1: 'harmony', 2: 'onionpir'}

        self.update_settings({
            'protocol': protocol_map.get(protocol_idx, 'dpf'),
            'server0_url': self._server0_input.text().strip(),
            'server1_url': self._server1_input.text().strip(),
            'sync_interval': self._interval_spin.value(),
        })

    def _update_status_display(self):
        """Update the status label with current sync info."""
        lines = []

        if not self._synchronizers:
            lines.append(_('No wallets loaded'))
        else:
            for wallet_id, sync in self._synchronizers.items():
                status = sync.get_status()
                lines.append(f"Wallet: {wallet_id[:8]}...")
                lines.append(f"  Running: {'Yes' if status['running'] else 'No'}")
                lines.append(f"  Addresses: {status['total_addresses']}")
                lines.append(f"  With UTXOs: {status['addresses_with_utxos']}")
                lines.append(f"  Total UTXOs: {status['total_utxos']}")
                btc = status['total_sats'] / 1e8
                lines.append(f"  Balance: {status['total_sats']} sats ({btc:.8f} BTC)")

                if status['last_sync'] > 0:
                    ago = time.time() - status['last_sync']
                    lines.append(f"  Last sync: {ago:.0f}s ago")
                else:
                    lines.append("  Last sync: never")

        if self._pir_client:
            lines.append('')
            lines.append(f"PIR Protocol: {self.pir_protocol}")
            lines.append(f"Connected: {'Yes' if self._pir_client.is_connected else 'No'}")
            if self._pir_client.index_bins > 0:
                lines.append(f"Index bins: {self._pir_client.index_bins:,}")
                lines.append(f"Chunk bins: {self._pir_client.chunk_bins:,}")

        self._status_label.setText('\n'.join(lines) if lines else _('Initializing...'))
