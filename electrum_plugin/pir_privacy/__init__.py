"""
BitcoinPIR - Privacy-preserving UTXO lookup for Electrum.

Supports three PIR backends (configurable):
  1. DPF 2-server — information-theoretic privacy
  2. HarmonyPIR 2-server — stateful PIR with offline hints
  3. OnionPIRv2 1-server — FHE-based, slower
"""

try:
    from electrum.i18n import _
except ImportError:
    def _(x): return x  # Fallback for standalone usage without Electrum

fullname = _('PIR Privacy')
description = _('Replace Electrum server queries with Private Information Retrieval. '
                'The server learns nothing about which addresses you own.')
available_for = ['qt', 'cmdline']
