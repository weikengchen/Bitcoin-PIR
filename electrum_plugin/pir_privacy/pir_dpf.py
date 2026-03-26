"""
Distributed Point Function (DPF) implementation - Python port of libdpf-ts.

Implements the core DPF algorithms from
"Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16)

Key compatibility: produces keys that are byte-identical to the TypeScript
implementation and can be evaluated by the Rust server.

Requires: cryptography (for AES-ECB)
"""

from __future__ import annotations

import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------------
# Block – 128-bit value stored as (high, low) pair of 64-bit integers
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1


class Block:
    """128-bit block represented as two 64-bit unsigned integers (high, low).

    Memory layout matches the C / TypeScript implementation:
    bytes 0-7 = low  (little-endian uint64)
    bytes 8-15 = high (little-endian uint64)
    """

    __slots__ = ("high", "low")

    def __init__(self, high: int, low: int) -> None:
        self.high = high & _MASK64
        self.low = low & _MASK64

    # -- factories ----------------------------------------------------------

    @staticmethod
    def zero() -> Block:
        return Block(0, 0)

    @staticmethod
    def from_bytes(data: bytes | bytearray | memoryview) -> Block:
        if len(data) != 16:
            raise ValueError("Block requires exactly 16 bytes")
        low, high = struct.unpack_from("<QQ", data)
        return Block(high, low)

    # -- serialisation ------------------------------------------------------

    def to_bytes(self) -> bytes:
        return struct.pack("<QQ", self.low, self.high)

    # -- arithmetic / bit ops -----------------------------------------------

    def xor(self, other: Block) -> Block:
        return Block(self.high ^ other.high, self.low ^ other.low)

    def lsb(self) -> int:
        return self.low & 1

    def reverse_lsb(self) -> Block:
        return Block(self.high, self.low ^ 1)

    def set_lsb_zero(self) -> Block:
        if self.lsb() == 1:
            return self.reverse_lsb()
        return self

    def left_shift(self, n: int) -> Block:
        if n == 0:
            return self
        if n >= 128:
            return Block.zero()
        if n >= 64:
            return Block((self.low << (n - 64)) & _MASK64, 0)
        new_low = (self.low << n) & _MASK64
        new_high = ((self.high << n) | (self.low >> (64 - n))) & _MASK64
        return Block(new_high, new_low)

    def equals(self, other: Block) -> bool:
        return self.low == other.low and self.high == other.high

    def is_zero(self) -> bool:
        return self.low == 0 and self.high == 0

    def __repr__(self) -> str:
        return f"Block({self.high:#x}, {self.low:#x})"


# ---------------------------------------------------------------------------
# AES-ECB based PRG
# ---------------------------------------------------------------------------

class AesKey:
    """AES-128 key wrapper using ECB mode."""

    def __init__(self, key_block: Block) -> None:
        key_bytes = key_block.to_bytes()
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        self._encryptor = cipher.encryptor()

    def encrypt_block(self, block: Block) -> Block:
        ct = self._encryptor.update(block.to_bytes())
        return Block.from_bytes(ct)


class Prg:
    """Pseudorandom Generator for DPF, built on AES-128-ECB.

    generate(input) -> (output0, output1, bit0, bit1)

    The input block's LSB is zeroed, then two plaintexts are formed
    (one with LSB=0, one with LSB=1), each encrypted and XORed back
    with the zeroed input to produce two pseudorandom output blocks
    and two control bits.
    """

    def __init__(self, key: Block) -> None:
        self._aes = AesKey(key)

    def generate(self, inp: Block) -> tuple[Block, Block, int, int]:
        # Zero the LSB
        stash0 = inp.set_lsb_zero()
        stash1 = stash0.reverse_lsb()

        # Encrypt both blocks
        stash0 = self._aes.encrypt_block(stash0)
        stash1 = self._aes.encrypt_block(stash1)

        # XOR with input (LSB zeroed)
        input_zeroed = inp.set_lsb_zero()
        stash0 = stash0.xor(input_zeroed)
        stash1 = stash1.xor(input_zeroed)
        stash1 = stash1.reverse_lsb()

        # Extract control bits
        bit0 = stash0.lsb()
        bit1 = stash1.lsb()

        # Zero LSBs in outputs
        output0 = stash0.set_lsb_zero()
        output1 = stash1.set_lsb_zero()

        return output0, output1, bit0, bit1


# ---------------------------------------------------------------------------
# DpfKey – serialisation format matching C / TypeScript / Rust
# ---------------------------------------------------------------------------

class DpfKey:
    """A DPF key for evaluation.

    Key format (matching C implementation):
      Byte 0:            n  (domain parameter)
      Bytes 1-16:        s0 (initial seed block, 16 bytes)
      Byte 17:           t0 (initial control bit)
      For each layer i in 1..maxlayer:
        Bytes [18*i .. 18*i+16):  scw[i-1]       (correction word block)
        Byte  18*i+16:            tcw[i-1][0]     (left correction bit)
        Byte  18*i+17:            tcw[i-1][1]     (right correction bit)
      Final 16 bytes:    finalBlock
    """

    __slots__ = ("n", "s0", "t0", "scw", "tcw", "final_block")

    def __init__(
        self,
        n: int,
        s0: Block,
        t0: int,
        scw: list[Block],
        tcw: list[tuple[int, int]],
        final_block: Block,
    ) -> None:
        self.n = n
        self.s0 = s0
        self.t0 = t0
        self.scw = scw
        self.tcw = tcw
        self.final_block = final_block

    def max_layer(self) -> int:
        return self.n - 7

    def size(self) -> int:
        ml = self.max_layer()
        return 1 + 16 + 1 + 18 * ml + 16

    def to_bytes(self) -> bytes:
        buf = bytearray(self.size())
        buf[0] = self.n
        buf[1:17] = self.s0.to_bytes()
        buf[17] = self.t0

        for i, (cw, (tl, tr)) in enumerate(zip(self.scw, self.tcw)):
            off = 18 * (i + 1)
            buf[off : off + 16] = cw.to_bytes()
            buf[off + 16] = tl
            buf[off + 17] = tr

        final_off = 18 * (self.max_layer() + 1)
        buf[final_off : final_off + 16] = self.final_block.to_bytes()
        return bytes(buf)

    @staticmethod
    def from_bytes(data: bytes | bytearray | memoryview) -> DpfKey:
        if len(data) < 18:
            raise ValueError("Key too short")
        n = data[0]
        maxlayer = n - 7
        expected = 1 + 16 + 1 + 18 * maxlayer + 16
        if len(data) < expected:
            raise ValueError(
                f"Key has incorrect length: expected {expected}, got {len(data)}"
            )
        s0 = Block.from_bytes(data[1:17])
        t0 = data[17]
        scw: list[Block] = []
        tcw: list[tuple[int, int]] = []
        for i in range(maxlayer):
            off = 18 * (i + 1)
            scw.append(Block.from_bytes(data[off : off + 16]))
            tcw.append((data[off + 16], data[off + 17]))
        final_off = 18 * (maxlayer + 1)
        final_block = Block.from_bytes(data[final_off : final_off + 16])
        return DpfKey(n, s0, t0, scw, tcw, final_block)


# ---------------------------------------------------------------------------
# DPF gen / eval
# ---------------------------------------------------------------------------

# Default AES key (from C implementation)
DEFAULT_KEY_HIGH = 597349
DEFAULT_KEY_LOW = 121379


def _default_key() -> Block:
    return Block(DEFAULT_KEY_HIGH, DEFAULT_KEY_LOW)


def _get_bit(x: int, n: int, b: int) -> int:
    """Get bit *b* (1-indexed from the MSB side) of an *n*-bit value *x*."""
    return (x >> (n - b)) & 1


class Dpf:
    """DPF context for key generation and evaluation."""

    def __init__(self, key: Block | None = None) -> None:
        self.prg = Prg(key if key is not None else _default_key())

    @staticmethod
    def with_default_key() -> Dpf:
        return Dpf(_default_key())

    # -- gen ----------------------------------------------------------------

    def gen(self, alpha: int, n: int) -> tuple[DpfKey, DpfKey]:
        """Generate two DPF keys for a point function where f(alpha)=1.

        Parameters
        ----------
        alpha : int
            The target index (the point where f evaluates to 1).
        n : int
            Domain parameter -- the domain size is 2**n.

        Returns
        -------
        (k0, k1) : tuple[DpfKey, DpfKey]
        """
        maxlayer = n - 7

        # Seeds and control bits per layer, for both parties (index 0 and 1)
        s = [
            [Block.zero(), Block.zero()]
            for _ in range(maxlayer + 1)
        ]
        t: list[list[int]] = [
            [0, 0]
            for _ in range(maxlayer + 1)
        ]

        # Correction words
        scw = [Block.zero() for _ in range(maxlayer)]
        tcw: list[list[int]] = [[0, 0] for _ in range(maxlayer)]

        # Random initial seeds
        s[0][0] = Block.from_bytes(os.urandom(16))
        s[0][1] = Block.from_bytes(os.urandom(16))

        # Initial control bits
        t[0][0] = s[0][0].lsb()
        t[0][1] = t[0][0] ^ 1

        # Zero LSBs of initial seeds
        s[0][0] = s[0][0].set_lsb_zero()
        s[0][1] = s[0][1].set_lsb_zero()

        # Iterate through layers
        for i in range(1, maxlayer + 1):
            # PRG expand for both parties
            s0L, s0R, t0L, t0R = self.prg.generate(s[i - 1][0])
            s1L, s1R, t1L, t1R = self.prg.generate(s[i - 1][1])

            # Determine keep/lose based on alpha's bit at this position
            alpha_bit = _get_bit(alpha, n, i)
            keep = 0 if alpha_bit == 0 else 1
            lose = 1 - keep

            s0 = [s0L, s0R]
            s1 = [s1L, s1R]
            t0 = [t0L, t0R]
            t1 = [t1L, t1R]

            # Correction word for seeds
            scw[i - 1] = s0[lose].xor(s1[lose])

            # Correction bits
            tcw[i - 1][0] = t0[0] ^ t1[0] ^ alpha_bit ^ 1
            tcw[i - 1][1] = t0[1] ^ t1[1] ^ alpha_bit

            # Propagate for party 0
            if t[i - 1][0] == 1:
                s[i][0] = s0[keep].xor(scw[i - 1])
                t[i][0] = t0[keep] ^ tcw[i - 1][keep]
            else:
                s[i][0] = s0[keep]
                t[i][0] = t0[keep]

            # Propagate for party 1
            if t[i - 1][1] == 1:
                s[i][1] = s1[keep].xor(scw[i - 1])
                t[i][1] = t1[keep] ^ tcw[i - 1][keep]
            else:
                s[i][1] = s1[keep]
                t[i][1] = t1[keep]

        # Compute final correction block
        final_block = Block.zero().reverse_lsb()  # block with LSB = 1
        shift = alpha & 127
        final_block = final_block.left_shift(shift)
        final_block = final_block.reverse_lsb()

        # XOR with final seeds
        final_block = final_block.xor(s[maxlayer][0])
        final_block = final_block.xor(s[maxlayer][1])

        # Build keys
        scw_copy = list(scw)
        tcw_tuples: list[tuple[int, int]] = [(a, b) for a, b in tcw]

        k0 = DpfKey(n, s[0][0], t[0][0], scw_copy, list(tcw_tuples), final_block)
        k1 = DpfKey(n, s[0][1], t[0][1], scw_copy, list(tcw_tuples), final_block)
        return k0, k1

    # -- eval (single point) ------------------------------------------------

    def eval(self, key: DpfKey, x: int) -> Block:
        """Evaluate the DPF at a single point *x*."""
        maxlayer = key.max_layer()
        s = key.s0
        t = key.t0

        for i in range(1, maxlayer + 1):
            sL, sR, tL, tR = self.prg.generate(s)

            sL_c, sR_c, tL_c, tR_c = sL, sR, tL, tR
            if t == 1:
                sL_c = sL.xor(key.scw[i - 1])
                sR_c = sR.xor(key.scw[i - 1])
                tL_c = tL ^ key.tcw[i - 1][0]
                tR_c = tR ^ key.tcw[i - 1][1]

            x_bit = _get_bit(x, key.n, i)
            if x_bit == 0:
                s = sL_c
                t = tL_c
            else:
                s = sR_c
                t = tR_c

        # Final corrections
        res = s
        if t == 1:
            res = res.reverse_lsb()
        if t == 1:
            res = res.xor(key.final_block)
        return res

    # -- eval full ----------------------------------------------------------

    def eval_full(self, key: DpfKey) -> list[Block]:
        """Evaluate the DPF at all 2^(n-7) leaf nodes."""
        maxlayer = key.max_layer()
        maxlayeritem = 1 << maxlayer

        # Two layers for ping-pong evaluation
        s_layers = [
            [Block.zero() for _ in range(maxlayeritem)],
            [Block.zero() for _ in range(maxlayeritem)],
        ]
        t_layers = [
            [0] * maxlayeritem,
            [0] * maxlayeritem,
        ]

        s_layers[0][0] = key.s0
        t_layers[0][0] = key.t0
        curlayer = 1

        for i in range(1, maxlayer + 1):
            itemnumber = 1 << (i - 1)
            for j in range(itemnumber):
                sL, sR, tL, tR = self.prg.generate(s_layers[1 - curlayer][j])

                sL_c, sR_c, tL_c, tR_c = sL, sR, tL, tR
                if t_layers[1 - curlayer][j] == 1:
                    sL_c = sL.xor(key.scw[i - 1])
                    sR_c = sR.xor(key.scw[i - 1])
                    tL_c = tL ^ key.tcw[i - 1][0]
                    tR_c = tR ^ key.tcw[i - 1][1]

                s_layers[curlayer][2 * j] = sL_c
                t_layers[curlayer][2 * j] = tL_c
                s_layers[curlayer][2 * j + 1] = sR_c
                t_layers[curlayer][2 * j + 1] = tR_c

            curlayer = 1 - curlayer

        # Final results
        results: list[Block] = []
        for j in range(maxlayeritem):
            block = s_layers[1 - curlayer][j]
            if t_layers[1 - curlayer][j] == 1:
                block = block.reverse_lsb()
            if t_layers[1 - curlayer][j] == 1:
                block = block.xor(key.final_block)
            results.append(block)
        return results


# ---------------------------------------------------------------------------
# Convenience helpers (matching the TS top-level exports)
# ---------------------------------------------------------------------------

def dpf_gen(alpha: int, n: int) -> tuple[DpfKey, DpfKey]:
    """Generate DPF key pair for target *alpha* in domain 2^n."""
    dpf = Dpf.with_default_key()
    return dpf.gen(alpha, n)


def dpf_eval(key: DpfKey, x: int) -> Block:
    """Evaluate a DPF key at point *x*."""
    dpf = Dpf.with_default_key()
    return dpf.eval(key, x)


def dpf_eval_full(key: DpfKey) -> list[Block]:
    """Full-domain evaluation of a DPF key."""
    dpf = Dpf.with_default_key()
    return dpf.eval_full(key)


# ---------------------------------------------------------------------------
# Async wrapper matching the requested interface
# ---------------------------------------------------------------------------

async def dpf_gen_async(index: int, log_domain: int) -> tuple[bytes, bytes]:
    """Generate DPF key pair (key0, key1) for target index in 2^log_domain domain.

    Returns two byte arrays, one for each server.
    """
    k0, k1 = dpf_gen(index, log_domain)
    return k0.to_bytes(), k1.to_bytes()
