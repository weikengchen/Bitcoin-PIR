"""
Python cffi bindings for OnionPIRv2 C FFI layer.

Loads the compiled OnionPIRv2 shared library (libonionpir.so / .dylib)
and exposes the client-side operations needed for PIR queries.

Build the shared library:
  cd /path/to/OnionPIRv2
  mkdir build && cd build
  cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
  make -j$(nproc)
  # produces libonionpir.so or libonionpir.dylib
"""

from __future__ import annotations

import os
import ctypes
from ctypes import (
    c_uint8, c_uint64, c_size_t, c_int, c_char_p, c_void_p, c_double,
    POINTER, Structure, byref,
)
from typing import Optional


# ── C struct definitions ──────────────────────────────────────────────────


class CPirParamsInfo(Structure):
    _fields_ = [
        ('num_entries', c_uint64),
        ('entry_size', c_uint64),
        ('num_plaintexts', c_uint64),
        ('fst_dim_sz', c_uint64),
        ('other_dim_sz', c_uint64),
        ('poly_degree', c_uint64),
        ('coeff_val_cnt', c_uint64),
        ('db_size_mb', c_double),
        ('physical_size_mb', c_double),
    ]


class OnionBuf(Structure):
    _fields_ = [
        ('data', POINTER(c_uint8)),
        ('len', c_size_t),
    ]


# ── Library loader ────────────────────────────────────────────────────────


def _find_library() -> str:
    """Find the OnionPIR shared library."""
    candidates = [
        # Relative to this file
        os.path.join(os.path.dirname(__file__), 'libonionpir.so'),
        os.path.join(os.path.dirname(__file__), 'libonionpir.dylib'),
        # Common build locations
        os.path.expanduser('~/bitcoin-pir/OnionPIRv2/build/libonionpir.so'),
        os.path.expanduser('~/bitcoin-pir/OnionPIRv2/build/libonionpir.dylib'),
        # System paths
        'libonionpir.so',
        'libonionpir.dylib',
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise FileNotFoundError(
        'OnionPIR shared library not found. Build it with:\n'
        '  cd /path/to/OnionPIRv2 && mkdir -p build && cd build\n'
        '  cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON\n'
        '  make -j$(nproc)'
    )


_lib: Optional[ctypes.CDLL] = None


def _get_lib() -> ctypes.CDLL:
    """Load the OnionPIR shared library (lazy, cached)."""
    global _lib
    if _lib is None:
        path = _find_library()
        _lib = ctypes.cdll.LoadLibrary(path)
        _setup_signatures(_lib)
    return _lib


def _setup_signatures(lib: ctypes.CDLL):
    """Set up ctypes function signatures for type safety."""
    # onion_free_buf
    lib.onion_free_buf.argtypes = [OnionBuf]
    lib.onion_free_buf.restype = None

    # onion_get_params_info
    lib.onion_get_params_info.argtypes = [c_uint64]
    lib.onion_get_params_info.restype = CPirParamsInfo

    # Client functions
    lib.onion_client_new.argtypes = [c_uint64]
    lib.onion_client_new.restype = c_void_p

    lib.onion_client_free.argtypes = [c_void_p]
    lib.onion_client_free.restype = None

    lib.onion_client_new_from_sk.argtypes = [c_uint64, c_uint64, POINTER(c_uint8), c_size_t]
    lib.onion_client_new_from_sk.restype = c_void_p

    lib.onion_client_export_secret_key.argtypes = [c_void_p]
    lib.onion_client_export_secret_key.restype = OnionBuf

    lib.onion_client_get_id.argtypes = [c_void_p]
    lib.onion_client_get_id.restype = c_uint64

    lib.onion_client_generate_galois_keys.argtypes = [c_void_p]
    lib.onion_client_generate_galois_keys.restype = OnionBuf

    lib.onion_client_generate_gsw_keys.argtypes = [c_void_p]
    lib.onion_client_generate_gsw_keys.restype = OnionBuf

    lib.onion_client_generate_query.argtypes = [c_void_p, c_uint64]
    lib.onion_client_generate_query.restype = OnionBuf

    lib.onion_client_decrypt_response.argtypes = [c_void_p, c_uint64, POINTER(c_uint8), c_size_t]
    lib.onion_client_decrypt_response.restype = OnionBuf


def _buf_to_bytes(buf: OnionBuf) -> bytes:
    """Convert an OnionBuf to Python bytes and free the C buffer."""
    lib = _get_lib()
    if buf.data is None or buf.len == 0:
        return b''
    result = bytes(buf.data[:buf.len])
    lib.onion_free_buf(buf)
    return result


# ── Python wrapper classes ────────────────────────────────────────────────


class PirParamsInfo:
    """OnionPIR parameter information."""

    def __init__(self, info: CPirParamsInfo):
        self.num_entries = info.num_entries
        self.entry_size = info.entry_size
        self.num_plaintexts = info.num_plaintexts
        self.fst_dim_sz = info.fst_dim_sz
        self.other_dim_sz = info.other_dim_sz
        self.poly_degree = info.poly_degree
        self.coeff_val_cnt = info.coeff_val_cnt
        self.db_size_mb = info.db_size_mb
        self.physical_size_mb = info.physical_size_mb

    def __repr__(self):
        return (f'PirParamsInfo(entries={self.num_entries}, '
                f'entry_size={self.entry_size}, '
                f'db_size={self.db_size_mb:.1f}MB)')


def get_params_info(num_entries: int = 0) -> PirParamsInfo:
    """Get OnionPIR parameters for a given database size."""
    lib = _get_lib()
    info = lib.onion_get_params_info(c_uint64(num_entries))
    return PirParamsInfo(info)


class OnionPirClientFFI:
    """
    Python wrapper for the OnionPIR FHE client.

    Handles key generation, query encryption, and response decryption.
    The heavy cryptographic work (BFV scheme) runs in the C++ library.

    Usage:
        client = OnionPirClientFFI(num_entries=1000)
        galois_keys = client.generate_galois_keys()
        gsw_keys = client.generate_gsw_keys()
        # Send keys to server for registration...

        query = client.generate_query(entry_index=42)
        # Send query to server, get response...
        entry_data = client.decrypt_response(42, response_bytes)
    """

    def __init__(self, num_entries: int = 0, secret_key: Optional[bytes] = None,
                 client_id: Optional[int] = None):
        """
        Create a new OnionPIR client.

        Args:
            num_entries: Database size (0 for compiled-in default)
            secret_key: Existing secret key (for key reuse across sessions)
            client_id: Client ID (required if secret_key is provided)
        """
        lib = _get_lib()

        if secret_key is not None and client_id is not None:
            sk_buf = (c_uint8 * len(secret_key))(*secret_key)
            self._handle = lib.onion_client_new_from_sk(
                c_uint64(num_entries),
                c_uint64(client_id),
                sk_buf, c_size_t(len(secret_key)),
            )
        else:
            self._handle = lib.onion_client_new(c_uint64(num_entries))

        if self._handle is None:
            raise RuntimeError('Failed to create OnionPIR client')

    def __del__(self):
        self.close()

    def close(self):
        """Free the C++ client object."""
        if self._handle is not None:
            lib = _get_lib()
            lib.onion_client_free(self._handle)
            self._handle = None

    @property
    def client_id(self) -> int:
        """Get the client's unique ID."""
        lib = _get_lib()
        return lib.onion_client_get_id(self._handle)

    def export_secret_key(self) -> bytes:
        """Export the secret key for persistence across sessions."""
        lib = _get_lib()
        buf = lib.onion_client_export_secret_key(self._handle)
        return _buf_to_bytes(buf)

    def generate_galois_keys(self) -> bytes:
        """Generate Galois keys for server registration (~2-5 MB)."""
        lib = _get_lib()
        buf = lib.onion_client_generate_galois_keys(self._handle)
        return _buf_to_bytes(buf)

    def generate_gsw_keys(self) -> bytes:
        """Generate GSW keys for server registration (~1-2 MB)."""
        lib = _get_lib()
        buf = lib.onion_client_generate_gsw_keys(self._handle)
        return _buf_to_bytes(buf)

    def generate_query(self, entry_index: int) -> bytes:
        """
        Generate an encrypted query for a specific entry index.

        Returns FHE ciphertext bytes to send to the server.
        """
        lib = _get_lib()
        buf = lib.onion_client_generate_query(self._handle, c_uint64(entry_index))
        return _buf_to_bytes(buf)

    def decrypt_response(self, entry_index: int, response: bytes) -> bytes:
        """
        Decrypt the server's response and extract the entry data.

        Args:
            entry_index: The queried entry index (must match generate_query)
            response: FHE ciphertext response from the server

        Returns:
            Decrypted entry data bytes
        """
        lib = _get_lib()
        resp_buf = (c_uint8 * len(response))(*response)
        buf = lib.onion_client_decrypt_response(
            self._handle,
            c_uint64(entry_index),
            resp_buf, c_size_t(len(response)),
        )
        return _buf_to_bytes(buf)
