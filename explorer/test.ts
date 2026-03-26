/**
 * Quick integration test for bitcoin-pir-explorer.
 *
 * Tests:
 * 1. PirUtxoProvider — fetch UTXOs for a known address via DPF
 * 2. PirExplorer — fetchAddress and fetchTxHistory via PIR
 * 3. EsploraFallback — fetchBlockHeight
 *
 * Run: npx tsx test.ts
 */

// Polyfill WebSocket for Node.js (PIR clients are browser-first)
import WebSocket from 'ws';
(globalThis as any).WebSocket = WebSocket;

import { PirUtxoProvider, PirExplorer, EsploraFallback } from './src/index.js';

// A known address with UTXOs (Satoshi's genesis block coinbase — unspendable but in UTXO set)
// Using a more common test address instead
const TEST_ADDRESS = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';

async function testEsploraFallback() {
  console.log('\n=== Test: EsploraFallback ===');
  const esplora = new EsploraFallback();
  const height = await esplora.fetchBlockHeight();
  console.log(`Block height: ${height}`);
  console.log('Esplora fallback: OK');
}

async function testPirUtxoProvider() {
  console.log('\n=== Test: PirUtxoProvider (DPF) ===');
  const provider = new PirUtxoProvider({
    backend: {
      type: 'dpf',
      server0Url: 'wss://dpf1.chenweikeng.com',
      server1Url: 'wss://dpf2.chenweikeng.com',
    },
    onLog: (msg) => console.log(`  ${msg}`),
  });

  await provider.connect();
  console.log(`Connected: ${provider.isConnected()}`);

  const utxos = await provider.fetchUtxos(TEST_ADDRESS);
  console.log(`UTXOs found: ${utxos.length}`);
  for (const u of utxos.slice(0, 3)) {
    console.log(`  txid=${u.txid.slice(0, 16)}... vout=${u.vout} value=${u.value} sat`);
  }

  console.log(`scriptPubKey: ${provider.scriptPubKey(TEST_ADDRESS)}`);
  provider.disconnect();
  console.log('Provider: OK');
}

async function testPirExplorer() {
  console.log('\n=== Test: PirExplorer (DPF) ===');
  const explorer = new PirExplorer({
    backend: {
      type: 'dpf',
      server0Url: 'wss://dpf1.chenweikeng.com',
      server1Url: 'wss://dpf2.chenweikeng.com',
    },
    onLog: (msg) => console.log(`  ${msg}`),
  });

  await explorer.connect();
  console.log(`Connected: ${await explorer.isConnected()}`);

  const info = await explorer.fetchAddress(TEST_ADDRESS);
  console.log(`fetchAddress: balance=${info.balance} sat, txCount=${info.txCount}`);

  const history = await explorer.fetchTxHistory({ address: TEST_ADDRESS });
  console.log(`fetchTxHistory: ${history.length} entries`);
  for (const h of history.slice(0, 3)) {
    console.log(`  txId=${h.txId.slice(0, 16)}... blockHeight=${h.blockHeight} irreversible=${h.irreversible}`);
  }

  const blockHeight = await explorer.fetchBlockHeight();
  console.log(`fetchBlockHeight (Esplora): ${blockHeight}`);

  explorer.close();
  console.log('Explorer: OK');
}

async function main() {
  try {
    await testEsploraFallback();
    await testPirUtxoProvider();
    await testPirExplorer();
    console.log('\n=== All tests passed ===');
  } catch (err) {
    console.error('TEST FAILED:', err);
    process.exit(1);
  }
}

main();
