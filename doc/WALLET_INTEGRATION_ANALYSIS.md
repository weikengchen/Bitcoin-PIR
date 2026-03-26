# BitcoinPIR Integration Analysis: Electrum, bitcoinj, Neutrino/LND

## Executive Summary

This document analyzes how to integrate BitcoinPIR's privacy-preserving UTXO lookup
into three major Bitcoin light wallet ecosystems. Each wallet has a fundamentally
different architecture, creating different integration surfaces and challenges.

| Wallet | Current Privacy | Integration Difficulty | Best PIR Protocol | Primary Interface |
|--------|----------------|----------------------|-------------------|-------------------|
| Electrum | Worst (server sees all addresses) | Medium | HarmonyPIR (1-server) | Plugin or Synchronizer fork |
| bitcoinj | Bad (BIP 37 bloom filters broken) | Easiest | Any (UTXOProvider) | `UTXOProvider` interface |
| Neutrino (wallet only) | Good (filters are uniform) | Easy (existing UTXO DB) | DPF 2-server | `ChainSource` interface |
| Neutrino + LND (Lightning) | Good | Medium (needs LN extension protocol) | DPF 2-server | `ChainSource` + LN PIR ext |

---

## 1. Electrum Integration

### 1.1 Current Architecture & Privacy Problem

Electrum connects to ElectrumX/Fulcrum servers via JSON-RPC over TCP/SSL. The wallet
synchronization flow is:

```
For each address in wallet:
  1. scripthash = reverse(SHA256(scriptPubKey))        ← Server learns this
  2. blockchain.scripthash.subscribe(scripthash)        ← Server links it to your IP
  3. blockchain.scripthash.get_history(scripthash)      ← Server sees your tx history
  4. blockchain.scripthash.listunspent(scripthash)      ← Server sees your UTXOs
  5. blockchain.transaction.get(txid)                   ← Server sees which txs you fetch
```

**The privacy leak is total**: the server learns every address in the wallet, can
cluster them (same TCP session), and correlates with IP address. Surveillance companies
are known to operate Electrum servers specifically for this data collection.

Existing mitigations (Tor, Electrum Personal Server) are either incomplete (Tor doesn't
fix address clustering) or impractical (EPS requires running a full node, defeating the
purpose of a light client).

### 1.2 Mapping BitcoinPIR to Electrum

**Critical compatibility issue**: Electrum uses `scripthash = reverse(SHA256(scriptPubKey))`
while BitcoinPIR uses `HASH160 = RIPEMD160(SHA256(scriptPubKey))`. These are different
hash functions with different output sizes (32 bytes vs 20 bytes).

**Resolution options**:
1. **Dual-index the PIR database**: Add an Electrum-compatible index keyed by SHA256
   scripthash alongside the existing HASH160 index. The database builder (`gen_2_build_index_cuckoo`)
   would produce a second set of cuckoo tables using 32-byte SHA256 keys.
2. **Client-side translation**: The Electrum plugin computes HASH160 from the scriptPubKey
   directly (before the Electrum scripthash derivation) and queries BitcoinPIR's existing
   HASH160-indexed database. This is simpler and requires no server-side changes.
   **This is the recommended approach.**

**Query mapping**:

| Electrum Method | BitcoinPIR Equivalent | Coverage |
|----------------|----------------------|----------|
| `scripthash.listunspent` | Full PIR query (index → chunk → UTXOs) | Complete |
| `scripthash.get_balance` | Sum amounts from PIR UTXO results | Complete |
| `scripthash.subscribe` | Poll PIR periodically for changes | Partial (no push) |
| `scripthash.get_history` | Not covered (PIR indexes UTXOs, not history) | Gap |
| `transaction.get` | Not covered (need separate tx fetch) | Gap |
| `transaction.broadcast` | Direct to Bitcoin P2P network | Separate channel |

### 1.3 Integration Architecture

#### Option A: Electrum Plugin (Recommended for adoption)

```
┌──────────────────────────────────────────────┐
│                 Electrum Wallet               │
│  ┌──────────────┐    ┌─────────────────────┐ │
│  │  wallet.py    │    │  synchronizer.py    │ │
│  │  (keys, txs)  │◄───│  (sync engine)      │ │
│  └──────────────┘    └────────┬────────────┘ │
│                               │               │
│  ┌────────────────────────────▼─────────────┐ │
│  │         PIR Plugin (pir_privacy.py)       │ │
│  │  ┌─────────────┐  ┌──────────────────┐   │ │
│  │  │ PIR Client   │  │ UTXO Cache       │   │ │
│  │  │ (WebSocket)  │  │ (scripthash→utxo)│   │ │
│  │  └──────┬──────┘  └──────────────────┘   │ │
│  └─────────┼────────────────────────────────┘ │
└────────────┼──────────────────────────────────┘
             │ WebSocket
    ┌────────▼────────┐
    │  PIR Server(s)  │
    │  (no address    │
    │   knowledge)    │
    └─────────────────┘
```

**Implementation approach**:

The plugin would monkey-patch or wrap key methods in `synchronizer.py`:

```python
# Pseudocode for PIR plugin
class PirPrivacyPlugin(BasePlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.pir_client = HarmonyPirClient(server_url)  # or BatchPirClient for 2-server
        self.utxo_cache = {}

    def on_network_start(self, network):
        # Replace synchronizer's subscription mechanism
        original_subscribe = network.synchronizer._subscribe_to_address

        async def pir_subscribe(addr):
            scripthash = address_to_scripthash(addr)
            script_pubkey = address_to_script(addr)
            hash160 = hash160(script_pubkey)

            # Query via PIR instead of sending scripthash to server
            utxos = await self.pir_client.query(hash160)
            self.utxo_cache[scripthash] = utxos

            # Feed results back into wallet without server contact
            network.synchronizer.wallet.receive_utxo_update(addr, utxos)

        network.synchronizer._subscribe_to_address = pir_subscribe
```

**Challenges**:
- Electrum's subscription model is push-based (server notifies on status change).
  PIR is pull-based. The plugin would need to poll periodically.
- Transaction history is not available via PIR. The plugin could fetch transactions
  from the P2P network directly (less privacy-critical since txids are public).
- The `aiorpcx` async framework must be respected — PIR queries need to be async-compatible.

#### Option B: Local Proxy Server

Run a lightweight local server that speaks the ElectrumX protocol but translates
queries to PIR behind the scenes:

```
Electrum ──JSON-RPC──► localhost:50001 ──PIR──► PIR Server(s)
                       (PIR Proxy)
```

The proxy implements the ElectrumX protocol methods and translates:
- `blockchain.scripthash.listunspent(sh)` → PIR query for HASH160(script)
- `blockchain.scripthash.get_balance(sh)` → sum PIR results
- `blockchain.scripthash.subscribe(sh)` → register for periodic PIR polling

**Advantages**: No Electrum code changes. Works with `--oneserver --server localhost:50001:t`.
**Disadvantages**: Extra process to run. Still needs to handle history/tx gaps.

### 1.4 Handling the Gaps

**Transaction history gap**: BitcoinPIR indexes the current UTXO set, not historical
transactions. Options:
1. **Hybrid mode**: Use PIR for UTXO queries, fetch history from a random Electrum
   server over Tor (weaker but pragmatic).
2. **Extended PIR database**: Build a second PIR database indexing transaction history
   by scripthash. Significantly larger database but architecturally clean.
3. **P2P block scanning**: Download compact block filters (BIP 157) to find relevant
   blocks, then fetch full blocks from random peers. Most private but slowest.

**Mempool/unconfirmed transactions**: PIR database is a snapshot. Unconfirmed
transactions must come from another source. Options: P2P network `inv`/`tx` messages,
or accept that unconfirmed balance updates are delayed until confirmation.

### 1.5 Recommended PIR Protocol

**HarmonyPIR (1-server stateful)** is the best fit for Electrum because:
- Electrum users already trust a single server — replacing one trusted server with
  one PIR server is the same trust model
- HarmonyPIR's offline/online split maps well to Electrum's startup flow:
  hints can be fetched at first launch, then queries are fast
- The WASM client can be compiled to native Python via pybind11 or called as subprocess
- Lower infrastructure requirement (1 server vs 2 for DPF)

**Performance estimate for typical wallet**:
- ~100 addresses (20 external + 20 internal × ~3 accounts with gap limit)
- Batch PIR can handle 75 queries per round (K=75)
- 2 rounds for index lookup, 2 rounds for chunk retrieval
- Total: ~200-600ms for full wallet sync (vs ~1-2s for current Electrum)

---

## 2. bitcoinj Integration

### 2.1 Current Architecture & Privacy Problem

bitcoinj implements BIP 37 Bloom Filter SPV:

```
1. Wallet generates bloom filter containing all watched pubkeys + pubkeyhashes
2. filterload message sends bloom filter to connected full node
3. Full node sends merkleblock + matching transactions for each new block
4. Wallet processes matched transactions
```

**The privacy is fundamentally broken**:
- Inserting both pubkey AND pubkeyhash gives effective FP rate of fp^2
- With default 271 pre-generated keys: effective fp = 0.0000000213
- Against ~56M pubkeys on chain: ~1.19 expected false positives (essentially zero cover)
- Intersection attacks across filter restarts eliminate remaining false positives
- Academic proof: Gervais et al. (2014), Nick (2015)

Even Bisq's fork with nonce persistence and pubkey exclusion only raises the attack
cost, not the privacy guarantees.

### 2.2 Mapping BitcoinPIR to bitcoinj

**The `UTXOProvider` interface is a near-perfect fit**:

```java
public interface UTXOProvider {
    List<UTXO> getOpenTransactionOutputs(List<Address> addresses)
        throws UTXOProviderException;
    int getChainHeadHeight() throws UTXOProviderException;
    NetworkParameters getParams();
}
```

BitcoinPIR's query returns exactly what `getOpenTransactionOutputs` needs:
- TXID (32 bytes) — from chunk data
- vout (varint) — from chunk data
- amount (varint) — from chunk data

The mapping is direct:

```java
public class PirUtxoProvider implements UTXOProvider {

    private final PirClient pirClient;  // WebSocket client to PIR server(s)

    @Override
    public List<UTXO> getOpenTransactionOutputs(List<Address> addresses)
            throws UTXOProviderException {
        List<UTXO> result = new ArrayList<>();

        for (Address addr : addresses) {
            byte[] scriptPubKey = ScriptBuilder.createOutputScript(addr).getProgram();
            byte[] hash160 = Utils.sha256hash160(scriptPubKey);  // HASH160

            // PIR query — server learns nothing about which hash160 was queried
            PirQueryResult pirResult = pirClient.query(hash160);

            if (pirResult != null) {
                for (UtxoEntry entry : pirResult.getEntries()) {
                    UTXO utxo = new UTXO(
                        Sha256Hash.wrap(entry.getTxId()),
                        entry.getVout(),
                        Coin.valueOf(entry.getAmount()),
                        pirResult.getBlockHeight(),  // from server info
                        false,  // not coinbase (or determine from data)
                        ScriptBuilder.createOutputScript(addr)
                    );
                    result.add(utxo);
                }
            }
        }
        return result;
    }

    @Override
    public int getChainHeadHeight() throws UTXOProviderException {
        return pirClient.getServerInfo().getBlockHeight();
    }
}
```

**Usage is one line**:
```java
wallet.setUTXOProvider(new PirUtxoProvider(pirClient));
```

### 2.3 Integration Architecture

```
┌─────────────────────────────────────────────────────┐
│              bitcoinj-based Wallet App               │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────┐ │
│  │  Wallet   │  │ BlockChain │  │ PeerGroup        │ │
│  │          │  │ (headers)  │  │ (P2P for headers  │ │
│  │ setUTXO- │  │            │  │  + tx broadcast)  │ │
│  │ Provider()│  │            │  │ [bloom filters    │ │
│  └────┬─────┘  └────────────┘  │  DISABLED]        │ │
│       │                         └──────────────────┘ │
│  ┌────▼──────────────────────────┐                   │
│  │  PirUtxoProvider              │                   │
│  │  implements UTXOProvider      │                   │
│  │  ┌────────────────────────┐   │                   │
│  │  │ PirClient (WebSocket)  │   │                   │
│  │  │ - DPF key generation   │   │                   │
│  │  │ - Response XOR decode  │   │                   │
│  │  │ - Cuckoo hash logic    │   │                   │
│  │  └──────────┬─────────────┘   │                   │
│  │  ┌──────────┴─────────────┐   │                   │
│  │  │ WalletExtension:       │   │                   │
│  │  │ PIR state (hints, PRP) │   │                   │
│  │  └────────────────────────┘   │                   │
│  └───────────────┬───────────────┘                   │
└──────────────────┼───────────────────────────────────┘
                   │ WebSocket
          ┌────────▼────────┐
          │  PIR Server(s)  │
          └─────────────────┘
```

### 2.4 Implementation Plan

**Phase 1: Java PIR Client Library**

Port the TypeScript/WASM PIR client logic to Java:

```
pir-client-java/
├── src/main/java/org/bitcoinpir/
│   ├── PirClient.java          // WebSocket connection management
│   ├── DpfKeyGen.java          // DPF key generation (JNI to libdpf or pure Java)
│   ├── CuckooHash.java         // Splitmix64, bucket derivation, cuckoo hashing
│   ├── Protocol.java           // Binary message encoding/decoding
│   ├── BatchPirClient.java     // 2-server DPF protocol
│   ├── HarmonyPirClient.java   // 1-server stateful protocol
│   └── PirUtxoProvider.java    // UTXOProvider implementation
```

**Key implementation choices**:
- **DPF key generation**: The most complex piece. Options:
  - JNI binding to the existing Rust `libdpf` — fastest, most reliable
  - Pure Java port — no native dependencies, easier distribution
  - WASM via GraalVM — reuse existing WASM build
- **WebSocket**: Use `java-websocket` or OkHttp WebSocket (already common in Android)
- **Crypto**: `java.security.MessageDigest` for SHA256, BouncyCastle for RIPEMD160
  (or bitcoinj's own RIPEMD160 implementation)

**Phase 2: WalletExtension for PIR State**

```java
public class PirStateExtension implements WalletExtension {
    private byte[] cachedHints;          // HarmonyPIR offline hints
    private byte[] prpKey;               // PRP key for relocation
    private long lastSyncHeight;         // Last successful PIR sync height

    @Override
    public String getWalletExtensionID() {
        return "org.bitcoinpir.state";
    }

    @Override
    public byte[] serializeWalletExtension() {
        // Serialize hints + PRP state for persistence
    }

    @Override
    public void deserializeWalletExtension(Wallet wallet, byte[] data) {
        // Restore PIR state on wallet load
    }
}
```

**Phase 3: Modified PeerGroup Behavior**

When using PIR, bloom filters should be disabled to prevent privacy leakage:

```java
// Option 1: Set bloom filter to match everything (download all, no leak)
peerGroup.setBloomFilterFalsePositiveRate(1.0);

// Option 2: Use PeerGroup only for headers + tx broadcast
// Skip filterload entirely, rely on UTXOProvider for balance
```

Block headers are still needed for SPV validation. These can come from P2P (no privacy
issue — all clients request headers) or from a separate headers-only service.

### 2.5 Advantages of bitcoinj Integration

1. **Cleanest API boundary**: `UTXOProvider` was designed exactly for this use case
2. **Widest reach**: One integration covers Bitcoin Wallet for Android, Bisq, and
   many other apps built on bitcoinj
3. **Java ecosystem**: Rich WebSocket libraries, JNI support, Android compatibility
4. **No bloom filters needed**: PIR completely replaces the broken BIP 37 mechanism
5. **WalletExtension**: Built-in persistence for PIR client state

### 2.6 Challenges

1. **DPF in Java**: No existing Java DPF library. Need JNI binding or pure Java port.
2. **Continuous monitoring**: `UTXOProvider` is pull-based. For real-time updates,
   need periodic polling or a hybrid approach with P2P for new block notifications.
3. **Transaction history**: Like Electrum, PIR gives UTXOs but not full tx history.
   bitcoinj's `Wallet` tracks transactions — need to handle the history gap.
4. **SPV proof**: bitcoinj validates merkle proofs from filtered blocks. With PIR,
   the UTXO data is not accompanied by a merkle proof. Need to either:
   - Trust the PIR server's data (acceptable for many use cases)
   - Add merkle proof of UTXO inclusion in the UTXO set commitment (requires
     Bitcoin consensus changes like utreexo)
   - Verify against block headers via compact block filters

### 2.7 Recommended PIR Protocol

**Any protocol works**, but **DPF 2-server** is recommended for production because:
- Bitcoin Wallet for Android already connects to multiple peers — the 2-server model
  is not a usability regression
- DPF has no offline phase — simpler for mobile where storage is constrained
- The non-collusion assumption is reasonable when servers are run by different entities

For a single-server deployment (e.g., a wallet developer running their own infra),
**HarmonyPIR** with hints cached via `WalletExtension` is ideal.

---

## 3. Neutrino/LND Integration

### 3.1 Current Architecture & Privacy Model

Neutrino implements BIP 157/158 Compact Block Filters:

```
1. Download ALL compact block filters (deterministic, same for every client)
2. For each filter, check locally if any watched scriptPubKey matches
3. If match → download full block from a peer, extract relevant transactions
4. If no match → skip block entirely
```

**Privacy is already good**: filter downloads reveal nothing (everyone downloads
the same filters). The remaining leak is the **selective block download pattern** —
a peer serving blocks can infer which blocks contain the client's transactions.

BIP 157 itself explicitly anticipates PIR: "clients may opt to anonymously fetch blocks
using advanced techniques such as Private Information Retrieval."

### 3.2 Deep Dive: Does Neutrino Actually Need Full Blocks or Full Transactions?

The initial assumption was that Neutrino fundamentally needs full blocks, making PIR
integration require a massive block-indexed PIR database (~1.3 TB). **Deeper analysis
reveals this is not the case.** Furthermore, the need for full transaction data
**splits cleanly into two layers**: base wallet vs. Lightning.

#### What flows upward from block downloads

After `extractBlockMatches()` processes a full block, only **matched transactions**
(not the full block) flow to consumers via callbacks:

```
Full block (1.5 MB avg)
  └─► extractBlockMatches() scans all txs
       └─► OnFilteredBlockConnected(height, header, relevantTxs)
            └─► btcwallet receives: BlockMeta + []*TxRecord (relevant txs only)
```

The full block is used at the Neutrino layer for (a) filter verification and
(b) matching, but **what consumers receive is only the matched transactions plus
block metadata**.

#### Base wallet vs. Lightning: what actually needs full transaction data?

| Operation | Needs full tx? | Lightning-specific? | Notes |
|-----------|---------------|--------------------|----|
| **Receive detection** | Current design: yes | No | But could be replaced by UTXO query returning (outpoint, amount, pkScript) |
| **Spend detection** | Current design: yes | No | But only needs "spent" status, not the spending tx content |
| **Balance query** | No | N/A | Amount stored separately in wtxmgr credit records |
| **Sending** | No | N/A | Wallet constructs tx locally from UTXO data |
| **gettransaction RPC** | Yes | No | Returns hex-encoded full tx for display — could be fetched lazily |
| **UTXO script retrieval** | Current design: yes | No | wtxmgr stores scripts inside full tx, not separately — design artifact |
| **Channel close classification** | **Yes (fundamental)** | **YES** | Must analyze spending tx structure (sequence, outputs) |
| **Breach detection** | **Yes (fundamental)** | **YES** | Must compare spending tx against revoked states |
| **Preimage extraction** | **Yes (fundamental)** | **YES** | Must read witness data from spending tx |
| **HTLC resolution** | **Yes (fundamental)** | **YES** | Must track second-level spending txs |

**Key insight: Only Lightning channel operations fundamentally require full spending
transaction content.** The base Bitcoin wallet's need for full transactions in the
current btcwallet codebase is an **implementation artifact** — wtxmgr stores scripts
inside serialized transactions rather than independently, and it uses full block
downloads because that's what BIP 157 provides. But architecturally, a base wallet
only needs:

```
For each watched address:
  - List of UTXOs: [(txid, vout, amount, pkScript)]
  - Spent status: which UTXOs have been consumed
  - Confirmation status: at what height each UTXO was created
```

This is **exactly what BitcoinPIR already provides**.

#### Lightning-specific: full spending transaction requirements

LND's channel state machine needs the **complete spending transaction** (including
witness data) in four cases — **all Lightning-specific**:

1. **Close type classification**: Checks `TxIn[0].Sequence` to distinguish
   cooperative vs. unilateral closes, inspects `TxOut` values via `toSelfAmount()`

2. **Breach retribution**: Needs spending tx to extract output amounts at known
   indices. (Though PR #6347 showed the revocation log itself can be minimal —
   reduced from ~747 KB to ~28 KB per commitment.)

3. **HTLC preimage extraction**: Extracts the 32-byte preimage from the spending
   transaction's witness stack:
   - Taproot: `SpendingTx.TxIn[index].Witness[2]`
   - Legacy: `SpendingTx.TxIn[index].Witness[3]`
   This is **security-critical** for payment forwarding — without the preimage,
   LND cannot claim the upstream HTLC.

4. **Justice transaction construction**: Building penalty transactions requires
   knowing the exact outputs of the breach commitment tx to spend them.

### 3.3 Two-Layer Integration Strategy

The clean split between base wallet and Lightning needs enables a **two-layer
integration** — a base layer using the existing BitcoinPIR database, and an
optional Lightning extension protocol.

#### Layer 1: Base Wallet PIR (existing BitcoinPIR database — no changes needed)

For a Neutrino-based Bitcoin wallet **without Lightning**, the existing BitcoinPIR
UTXO database is sufficient:

```
Query:  HASH160(scriptPubKey)
Return: [{txid, vout, amount}]    ← Already implemented in BitcoinPIR
```

This covers:
- Balance queries (sum amounts)
- UTXO availability for constructing transactions
- Receive detection (new UTXOs appearing for watched addresses)
- Spend detection (UTXOs disappearing between queries)
- GetUtxo() — O(1) instead of O(chain_height) filter scanning

**No database extension needed. No new protocol needed. The existing BitcoinPIR
server works as-is for base Neutrino wallet functionality.**

```
┌──────────────────────────────────────────────┐
│        Neutrino Wallet (no Lightning)        │
│                                              │
│  ┌──────────────┐  ┌─────────────────────┐  │
│  │ Filter DL    │  │ PIR ChainSource     │  │
│  │ (P2P,private)│  │                     │  │
│  │              │  │ GetUtxo()──►PIR      │  │
│  │              │  │ Balance ──►PIR       │  │
│  │              │  │ Receive ──►PIR       │  │
│  └──────────────┘  └─────────┬───────────┘  │
└──────────────────────────────┼───────────────┘
                               │ WebSocket
                      ┌────────▼────────┐
                      │ Existing PIR    │
                      │ UTXO Server     │
                      │ (no changes)    │
                      └─────────────────┘
```

#### Layer 2: Lightning Extension Protocol (new, for LND channel operations)

Only when LND is performing Lightning-specific channel operations does it need
full spending transaction data. This is a **separate, targeted protocol** that
could be developed independently:

```
Lightning PIR Extension:
  Query:  HASH160(scriptPubKey) + flag indicating "full tx needed"
  Return: [{full serialized tx (with witness), block_height, block_hash,
            merkle_proof, spending_tx (if spent)}]
```

This extension serves four Lightning-specific operations:

1. **Close type classification** — needs spending tx structure
2. **Breach detection** — needs spending tx outputs at known indices
3. **Preimage extraction** — needs spending tx witness data
4. **Justice tx construction** — needs breach commitment tx outputs

```
┌──────────────────────────────────────────────────────────────┐
│                    LND (with Lightning)                       │
│                                                              │
│  ┌──────────────┐  ┌───────────────────┐  ┌──────────────┐ │
│  │ Filter DL    │  │ Base PIR (Layer 1) │  │ LN Extension │ │
│  │ (P2P)        │  │ UTXO queries      │  │ (Layer 2)    │ │
│  │              │  │ Balance, GetUtxo  │  │ Full tx for  │ │
│  │              │  │                   │  │ channel ops  │ │
│  └──────────────┘  └────────┬──────────┘  └──────┬───────┘ │
└─────────────────────────────┼────────────────────┼──────────┘
                              │                    │
                     ┌────────▼────────┐  ┌────────▼────────┐
                     │ Existing PIR    │  │ LN PIR Server   │
                     │ UTXO Server     │  │ (extended chunks│
                     │                 │  │  with full txs) │
                     └─────────────────┘  └─────────────────┘
```

#### Why this split matters

| Aspect | Layer 1 (Base Wallet) | Layer 2 (Lightning Extension) |
|--------|----------------------|------------------------------|
| Database | Existing BitcoinPIR UTXO DB | Extended DB with full tx + witness |
| DB size | ~7 GB (current) | ~10-20 GB (txs + merkle proofs) |
| Server changes | None | New chunk format with full tx data |
| Protocol changes | None | New query type or flag |
| Serves | All Neutrino wallets | Only LND with active channels |
| Development priority | Immediate (already works) | Can be developed later |
| Query frequency | Every sync (~100 queries) | Rare (channel events only) |

### 3.4 Extended PIR Database Design

The chunk data format would be extended:

```
Current BitcoinPIR chunk (40 bytes):
  [varint entry_count]
  [32B TXID][varint vout][varint amount] × entry_count

Extended chunk for LND (variable size):
  [varint entry_count]
  For each entry:
    [32B TXID][varint vout][varint amount]
    [varint tx_size][tx_size bytes: full serialized tx]
    [4B block_height][32B block_hash]
    [varint merkle_proof_len][merkle_proof bytes]
```

**Size impact**: Full transactions average ~400 bytes (segwit). With merkle proofs
(~320 bytes for a tree of depth 10), each entry grows from ~37 bytes to ~770 bytes.
This is ~20x larger per entry but still far smaller than storing full blocks.

**Alternative**: Keep the existing compact UTXO database (Tier 1) and add a
**separate** transaction database alongside it. LND queries Tier 1 for fast balance
checks and Tier 2/3 only when it needs full transaction data for channel operations.

### 3.5 Handling Filter Verification Without Full Blocks

Filter verification (`VerifyBasicBlockFilter`) is the one operation that genuinely
requires the full block — it recomputes the filter from all block transactions to
detect dishonest filter-serving peers. Options:

1. **Skip verification, trust filters from multiple peers**: Download filters from
   N peers and accept the majority. Weaker but practical. Neutrino already does
   checkpoint-based cross-peer verification.

2. **Probabilistic verification**: Periodically download a random full block to
   verify its filter. A lying peer would eventually be caught.

3. **Filter commitment (future)**: When Bitcoin adds filter commitments to the
   coinbase (proposed in BIP 157), filters become trustless without full blocks.

4. **Outsource verification**: A trusted server attests to filter correctness.
   Weaker trust model but compatible with PIR.

Option 1 combined with option 2 is the most practical near-term approach.

### 3.6 Implementation: PirChainSource

```go
type PirChainSource struct {
    // Existing BitcoinPIR client for UTXO queries (Tier 1)
    utxoClient  *pir.BatchPirClient

    // Extended PIR client for full tx retrieval (Tier 2/3)
    txClient    *pir.TxPirClient

    // Standard P2P for headers + filters (already private)
    headerStore headerfs.BlockHeaderStore
    filterStore filterdb.FilterDatabase
    p2pSource   *neutrino.ChainService  // fallback + headers
}

// Tier 1: O(1) UTXO existence check via PIR (replaces O(n) filter scan)
func (p *PirChainSource) GetUtxo(op *wire.OutPoint, pkScript []byte,
    heightHint uint32, cancel <-chan struct{}) (*wire.TxOut, error) {

    hash160 := btcutil.Hash160(pkScript)
    result, err := p.utxoClient.Query(hash160)
    if err != nil {
        return p.p2pSource.GetUtxo(op, pkScript, heightHint, cancel) // fallback
    }

    for _, entry := range result.Entries {
        if bytes.Equal(entry.TxID, op.Hash[:]) && entry.Vout == op.Index {
            return wire.NewTxOut(int64(entry.Amount), pkScript), nil
        }
    }
    return nil, ErrOutputSpent
}

// Tier 2: Fetch specific transactions matching a script via PIR
// (replaces downloading full block + scanning)
func (p *PirChainSource) GetRelevantTxs(pkScript []byte) ([]*TxWithProof, error) {
    hash160 := btcutil.Hash160(pkScript)
    return p.txClient.QueryFullTxs(hash160)
}

// Tier 3: Detect spending of a specific outpoint via PIR
func (p *PirChainSource) GetSpendingTx(op *wire.OutPoint, pkScript []byte) (*SpendDetail, error) {
    hash160 := btcutil.Hash160(pkScript)
    txs, err := p.txClient.QueryFullTxs(hash160)
    // ... search for tx that spends our outpoint
}

// Filters + headers from P2P (already private, no change)
func (p *PirChainSource) GetCFilter(hash chainhash.Hash, ...) (*gcs.Filter, error) {
    return p.filterStore.FetchFilter(&hash, filterType)
}

// For the rare case full block is needed (filter verification)
func (p *PirChainSource) GetBlock(hash chainhash.Hash, ...) (*btcutil.Block, error) {
    return p.p2pSource.GetBlock(hash, opts...) // fallback to P2P
}
```

### 3.7 LND Chain Backend Registration

```go
// In chainreg/chainregistry.go
case "neutrino-pir":
    pirUtxoClient := pir.NewBatchPirClient(cfg.Pir.Server0, cfg.Pir.Server1)
    pirTxClient := pir.NewTxPirClient(cfg.Pir.TxServer)
    pirChainSource := pir.NewChainSource(pirUtxoClient, pirTxClient, neutrinoCS)
    chainNotifier = neutrinonotify.New(pirChainSource, ...)
```

```bash
lnd --bitcoin.node=neutrino-pir \
    --pir.server0=wss://pir1.example.com:8091 \
    --pir.server1=wss://pir2.example.com:8092 \
    --pir.txserver=wss://pir-tx.example.com:8093
```

### 3.8 What Changes in BitcoinPIR's Database

To support Neutrino/LND, the build pipeline needs extension:

```
Existing pipeline (UTXO-only, Tier 1):
  gen_0 → gen_1 → gen_2 → gen_7
  Output: index cuckoo (scripthash → chunk location)
          chunk cuckoo (chunk_id → [txid, vout, amount])

New pipeline (extended, Tier 2/3):
  gen_0 → gen_1 → gen_1b_attach_full_txs → gen_2 → gen_7
  Output: index cuckoo (scripthash → chunk location)
          chunk cuckoo (chunk_id → [txid, vout, amount, full_tx, block_meta, merkle_proof])
```

The new `gen_1b_attach_full_txs` stage would:
1. For each UTXO entry, look up the full transaction from Bitcoin Core's txindex
2. Compute the merkle proof from the block's merkle tree
3. Attach this data to the chunk

### 3.9 Advantages of Transaction-Level PIR (vs Block-Level)

| Aspect | Block-Level PIR (old plan) | Transaction-Level PIR (revised) |
|--------|---------------------------|-------------------------------|
| Database size | ~1.3 TB (all blocks) | ~10-20 GB (UTXO-associated txs) |
| Server computation | Enormous (PIR over 1.5 MB items) | Manageable (PIR over ~1 KB items) |
| Client bandwidth | Download full blocks via PIR | Download only relevant txs |
| Privacy | Hides which block you want | Hides which scripthash you want |
| Existing infra | New database type needed | Extension of existing UTXO DB |
| GetUtxo speedup | No (still filter scanning) | Yes (O(1) via PIR) |

### 3.10 Remaining Challenges

1. **Full block for filter verification**: Still needed occasionally. Can fall back
   to P2P for this (infrequent, acceptable privacy trade-off).

2. **Ongoing monitoring**: PIR database is a snapshot. LND needs real-time spend
   detection. Options:
   - Poll PIR every N seconds for watched outpoints
   - Use P2P compact block filters for new blocks (already private), only use
     PIR for historical lookups
   - Hybrid: filters for "is there something new?", PIR for "give me the details"

3. **Extended chunk size**: Full transactions in chunks increase PIR response size
   and server computation. May need larger chunk allocation or multi-chunk responses.

4. **Go PIR client library**: Still needed (CGo to Rust libdpf or pure Go port).

### 3.11 Recommended PIR Protocol

**DPF 2-server** for both UTXO and transaction queries because:
- LND already manages multiple peer connections; 2 PIR servers is natural
- DPF has no offline phase — simpler deployment
- The non-collusion assumption works well when PIR servers are operated by
  different Lightning service providers (e.g., one by ACINQ, one by Lightning Labs)

For users who can only access one server, **HarmonyPIR** with hints cached in
LND's BoltDB store is the alternative.

---

## 4. Comparative Analysis

### 4.1 Integration Effort Estimate

| Component | Electrum | bitcoinj | Neutrino/LND |
|-----------|----------|----------|-------------|
| PIR client library | Python (easiest — can wrap existing TS/WASM) | Java (JNI or pure port) | Go (CGo or pure port) |
| API integration | Medium (monkey-patch synchronizer) | Easy (`UTXOProvider` interface) | Medium (`ChainSource` + extended UTXO DB) |
| State persistence | Plugin config files | `WalletExtension` (built-in) | BoltDB store |
| Missing data | History, mempool | History, SPV proofs | Extended chunks (full txs + merkle proofs) |
| Database changes | None (existing UTXO DB) | None (existing UTXO DB) | Extend chunks to include full tx data |
| Testing surface | Desktop + Android (same code) | Many downstream wallets | LND + standalone Neutrino |

### 4.2 Privacy Improvement Matrix

| Privacy Threat | Electrum Today | + PIR | bitcoinj Today | + PIR | Neutrino Today | + PIR |
|---------------|---------------|-------|----------------|-------|----------------|-------|
| Server learns addresses | Yes | **No** | Yes (bloom) | **No** | No | No |
| Address clustering | Yes | **No** | Yes | **No** | No | No |
| IP correlation | Yes (w/o Tor) | Orthogonal | Yes | Orthogonal | Yes | Orthogonal |
| Selective data leak | N/A | N/A | Filter analysis | **N/A** | Block download | **No** |
| Transaction timing | Yes | Reduced | Yes | Reduced | Partial | **No** |

### 4.3 Recommended Priority Order

1. **bitcoinj** (highest impact per effort)
   - Cleanest integration via `UTXOProvider`
   - Fixes the worst privacy problem (BIP 37 is completely broken)
   - Reaches the most downstream wallets
   - Java PIR client is a clear, scoped deliverable

2. **Electrum** (highest individual user impact)
   - Largest direct user base
   - Plugin system enables non-fork distribution
   - Python makes prototyping fast (can call WASM via subprocess initially)
   - Privacy improvement is dramatic (from "server sees everything" to "server sees nothing")

3. **Neutrino base wallet** (surprisingly easy — existing DB works)
   - A plain Neutrino Bitcoin wallet (no Lightning) only needs UTXO data
   - **The existing BitcoinPIR UTXO database works as-is — no changes needed**
   - Replaces the O(chain_height) filter scanning in `GetUtxo` with O(1) PIR lookup
   - Needs only a Go PIR client library + `ChainSource` implementation
   - BIP 157 explicitly anticipated PIR, giving strong alignment

4. **LND Lightning extension** (separate protocol, develop later)
   - Only Lightning channel operations need full spending transaction data
   - Four specific operations: close classification, breach detection,
     preimage extraction, justice tx construction
   - Can be developed as a targeted extension protocol on top of Layer 1
   - Extended database (~10-20 GB) with full tx + witness + merkle proofs
   - Rare queries (only on channel events, not every sync)

---

## 5. Shared Infrastructure

### 5.1 PIR Server Deployment

All three integrations share the same PIR server infrastructure:

```
┌──────────────────────────────────────────────────────┐
│                 PIR Server Cluster                    │
│                                                      │
│  ┌──────────────────┐  ┌─────────────────────────┐  │
│  │ UTXO PIR DB      │  │ Extended TX PIR DB       │  │
│  │ (Electrum,       │  │ (Neutrino/LND:           │  │
│  │  bitcoinj,       │  │  full txs + merkle       │  │
│  │  LND balance)    │  │  proofs for channel ops) │  │
│  └──────┬───────────┘  └──────┬──────────────────┘  │
│         │                     │                      │
│  ┌──────▼─────────────────────▼──────┐              │
│  │    PIR Server (Rust)               │              │
│  │    WebSocket on :8091/:8092        │              │
│  │    DPF eval + HarmonyPIR           │              │
│  └────────────────────────────────────┘              │
└──────────────────────────────────────────────────────┘
```

The existing BitcoinPIR server already handles UTXO queries (Tier 1). For
Neutrino/LND channel operations, the chunk data is extended to include full
transaction bytes and merkle proofs (Tier 2/3). Both databases use the same
PIR server infrastructure and the same scripthash-based indexing.

### 5.2 Database Update Pipeline

The UTXO set changes with every block. The PIR database must be periodically
rebuilt:

```
Bitcoin Core (dumptxoutset) ──► gen_0 ──► gen_1 ──► gen_2 ──► gen_7
                                 │         │         │         │
                               utxo_set  chunks   index_    chunk_
                               .bin       .bin     cuckoo    cuckoo
                                                   .bin      .bin
```

Update frequency options:
- **Every block** (~10 min): Most accurate, highest server load
- **Every N blocks** (e.g., 144 = ~1 day): Practical balance
- **On-demand**: Client checks server's block height, requests refresh if stale

### 5.3 Cross-Platform Client Libraries

The DPF key generation and cuckoo hashing logic needs to exist in:
- **TypeScript/WASM** (already done — web client)
- **Rust** (already done — CLI client)
- **Python** (for Electrum — can wrap WASM or Rust via PyO3)
- **Java** (for bitcoinj — JNI to Rust or pure Java port)
- **Go** (for Neutrino — CGo to Rust or pure Go port)

A **Rust core library with FFI bindings** is the most maintainable approach:

```
libbitcoinpir (Rust)
├── C FFI (cbindgen)
│   ├── Python binding (PyO3 or cffi)
│   ├── Java binding (JNI)
│   └── Go binding (CGo)
└── WASM (wasm-bindgen) ← already exists
```

---

## 6. Open Questions

1. **Database freshness**: How stale can the UTXO data be before it degrades UX?
   For balance checking, minutes are fine. For spending, the wallet needs to know
   the exact current UTXO set to construct valid transactions.

2. **Proof of inclusion**: Should the PIR response include a cryptographic proof
   that the UTXO exists in the Bitcoin UTXO set? Without proofs, the client trusts
   the PIR server's database. With utreexo commitments (not yet in Bitcoin consensus),
   this could be trustless.

3. **Address types**: BitcoinPIR indexes by HASH160(scriptPubKey). This works for
   all standard address types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) because they all
   have scriptPubKeys that can be HASH160'd. Verify that edge cases (bare multisig,
   OP_RETURN) are handled correctly.

4. **Dust filtering**: BitcoinPIR filters UTXOs ≤576 sats. Some wallets may want
   to see dust UTXOs. Make this configurable or document the limitation.

5. **Whale addresses**: Addresses with >100 UTXOs are flagged but not fully served.
   Major exchange cold wallets would hit this. Document or increase the limit.

6. **Server discovery**: How do wallet users find PIR servers? Options:
   - Hardcoded server list (like Electrum's server list)
   - DNS-based discovery
   - Wallet developer runs PIR servers as a service

7. **Incremental updates**: Can the PIR database support delta updates (only changed
   UTXOs) rather than full rebuilds? This would reduce server-side build time from
   minutes to seconds.

---

## Appendix: Electrum Plugin Implementation Status (2026-03-26)

### Completed Components

The Electrum plugin (`electrum_plugin/`) has been implemented and verified against
live PIR servers. All three PIR backends produce identical results.

#### Three PIR Backends — All Working

| Backend | Files | Status | Notes |
|---------|-------|--------|-------|
| DPF 2-Server | `pir_client.py` | Verified | ~1s query after connection |
| HarmonyPIR 2-Server | `pir_harmony_client.py` + `harmonypir-python/` (PyO3) | Verified | ~30s hint load, then ~2s/query |
| OnionPIRv2 1-Server | `pir_onionpir_client.py` + `onionpir-python/` (ctypes FFI) | Verified | ~50s/query, single server |

Test hash `20d920103ecb721638eb43f3e7a27c7b8ed3925b` returns identical results
across all three protocols: **100 UTXOs, 1,140,782,473 sats (11.40782473 BTC)**.

#### Architecture

```
electrum_plugin/
  pir_privacy/
    pir_client.py           # DPF 2-server BatchPirClient
    pir_harmony_client.py   # HarmonyPIR 2-server client
    pir_onionpir_client.py  # OnionPIRv2 1-server FHE client
    pir_hash.py             # Shared cuckoo hash, tag computation
    pir_constants.py        # K=75, K_CHUNK=80, sizes
    pir_ws_client.py        # WebSocket connection wrapper
    pir_protocol.py         # DPF wire protocol encode/decode
    pir_synchronizer.py     # Replaces Electrum's Synchronizer
    pir_plugin.py           # Electrum plugin entry point
  harmonypir-python/        # PyO3 Rust bindings for HarmonyPIR
    src/lib.rs              # Standalone reimplementation (no WASM dep)
    Cargo.toml
  onionpir-python/          # ctypes FFI for OnionPIR C++ library
    onionpir_ffi.py
```

#### Key Design Decisions

1. **Batch queries via PBC placement**: All three backends use Probabilistic Batch
   Codes to pack multiple address lookups into K=75 groups per round. A typical
   wallet (20-200 addresses) fits in 1-3 rounds.

2. **Poll-based sync (not push)**: The PirSynchronizer polls every ~30s instead of
   using Electrum's server-push model. Trade-off: ~30s latency vs. complete address
   privacy (server never learns which addresses you own).

3. **HarmonyPIR PyO3 is standalone**: The `harmonypir-python` crate wraps the core
   `harmonypir` Rust crate directly (PRP, RelocationDS), not the WASM crate. This
   avoids wasm-bindgen overhead. Critical: `derive_bucket_key` XORs bucket_id into
   bytes 12-15 (not 0-3), and `find_best_t` uses `sqrt(2n).round()`.

4. **OnionPIR single key registration**: Unlike DPF/HarmonyPIR (which use per-bucket
   keys), OnionPIR registers one shared FHE key pair, then creates per-level clients
   from the same secret key.

#### Remaining Work

- [ ] End-to-end test with actual Electrum wallet (GUI integration)
- [ ] HarmonyPIR hint caching to disk (avoid 30s reload on restart)
- [ ] OnionPIR secret key caching (avoid re-registration)
- [ ] bitcoinj integration (Java UTXOProvider — separate project)
- [ ] Performance benchmarking with multiple addresses
