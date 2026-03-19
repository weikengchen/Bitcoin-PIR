use bitcoin::bip158::{self, BlockFilter, BlockFilterWriter};
use bitcoin::block::Block;
use bitcoin::BlockHash;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub mod utils;

pub struct BlockIndexer {
    utxo_set: HashMap<bitcoin::OutPoint, bitcoin::ScriptBuf>,
}

impl BlockIndexer {
    pub fn new() -> Self {
        Self {
            utxo_set: HashMap::new(),
        }
    }

    pub fn add_block(&mut self, block: &Block) -> Result<(BlockFilter, u32), bip158::Error> {
        let mut tx_count = 0;

        for tx in block.txdata.iter() {
            tx_count += 1;

            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = bitcoin::OutPoint {
                    txid: tx.compute_txid(),
                    vout: vout as u32,
                };
                self.utxo_set.insert(outpoint, output.script_pubkey.clone());
            }
        }

        let mut filter_data = Vec::new();
        {
            let mut writer = BlockFilterWriter::new(&mut filter_data, block);
            writer.add_output_scripts();
            writer.add_input_scripts(|outpoint| {
                self.utxo_set
                    .get(outpoint)
                    .cloned()
                    .ok_or_else(|| bip158::Error::UtxoMissing(outpoint.clone()))
            })?;
            writer.finish()?;
        }

        Ok((BlockFilter::new(&filter_data), tx_count))
    }

    pub fn create_filter_for_block(
        block: &Block,
        utxo_set: &HashMap<bitcoin::OutPoint, bitcoin::ScriptBuf>,
    ) -> Result<BlockFilter, bip158::Error> {
        let mut filter_data = Vec::new();
        {
            let mut writer = BlockFilterWriter::new(&mut filter_data, block);
            writer.add_output_scripts();
            writer.add_input_scripts(|outpoint| {
                utxo_set
                    .get(outpoint)
                    .cloned()
                    .ok_or_else(|| bip158::Error::UtxoMissing(outpoint.clone()))
            })?;
            writer.finish()?;
        }

        Ok(BlockFilter::new(&filter_data))
    }

    pub fn save_filter<P: AsRef<Path>>(
        block_hash: BlockHash,
        filter: &BlockFilter,
        output_dir: P,
    ) -> Result<(), bip158::Error> {
        let filter_path = output_dir.as_ref().join(format!("{:x}.filter", block_hash));
        let file = File::create(filter_path).map_err(|e| bip158::Error::Io(e.into()))?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(&filter.content)
            .map_err(|e| bip158::Error::Io(e.into()))?;
        writer.flush().map_err(|e| bip158::Error::Io(e.into()))?;
        Ok(())
    }

    pub fn load_filter<P: AsRef<Path>>(filter_path: P) -> Result<BlockFilter, bip158::Error> {
        let data = std::fs::read(filter_path).map_err(|e| bip158::Error::Io(e.into()))?;
        Ok(BlockFilter::new(&data))
    }

    pub fn filter_matches_any(
        filter: &BlockFilter,
        block_hash: &BlockHash,
        scripts: &[bitcoin::ScriptBuf],
    ) -> Result<bool, bip158::Error> {
        filter.match_any(block_hash, &mut scripts.iter().map(|s| s.as_bytes()))
    }

    pub fn filter_matches_all(
        filter: &BlockFilter,
        block_hash: &BlockHash,
        scripts: &[bitcoin::ScriptBuf],
    ) -> Result<bool, bip158::Error> {
        filter.match_all(block_hash, &mut scripts.iter().map(|s| s.as_bytes()))
    }
}
