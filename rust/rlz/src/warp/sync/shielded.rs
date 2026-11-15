use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use anyhow::{Context as _, Result};
use bincode::config::legacy;
use futures::TryStreamExt;
use rayon::prelude::*;
use sqlx::{Row, SqliteConnection};
use tokio::sync::mpsc::Sender;
use tracing::{debug, enabled};
use zcash_trees::network::Network;

use crate::lwd::{CompactBlock, CompactIssueNote, CompactTx};
use crate::net::CompletedSubtree;
use crate::warp::{Edge, Hasher, OutputRef, Witness, MERKLE_DEPTH};
use crate::Hash32;
use ::orchard::issuance::auth::{IssueValidatingKey, ZSASchnorr};
use ::orchard::note::{AssetBase, AssetId};
use zcash_trees::types::{Note, Transaction, WarpSyncMessage, UTXO};

pub mod ironwood;
pub mod orchard;
pub mod sapling;

pub trait ShieldedProtocol {
    type Hasher: Hasher;
    type IVK: Sync;
    type NK: Sync;
    type Note: Sync + Send;
    type Spend;
    type Output: Sync;

    /// Issuance key type. Set to `()` for all protocols — issuance note
    /// synthesis has been removed in favor of trial decryption via actions.
    type IssueAuth: Sync;

    fn extract_ivk(
        connection: &mut SqliteConnection,
        account: u32,
        scope: u8,
    ) -> impl std::future::Future<Output = Result<Option<(Self::IVK, Self::NK)>>>;
    fn extract_inputs(tx: &CompactTx) -> &Vec<Self::Spend>;
    fn extract_outputs(tx: &CompactTx) -> &Vec<Self::Output>;

    fn extract_nf(i: &Self::Spend) -> Hash32;
    fn extract_cmx(o: &Self::Output) -> Hash32;

    /// Every (key index, note) match of `outputs` against `keys`, output-major, key-minor.
    fn try_decrypt_batch(
        network: &Network,
        keys: &[(u32, u8, &Self::IVK)],
        outputs: &[OutputRef<Self::Output>],
    ) -> Vec<(usize, Self::Note, Note)>;

    fn derive_nf(nk: &Self::NK, position: u32, note: &mut Self::Note) -> Result<Hash32>;

    /// Process a plaintext issuance note. No trial decryption — the note fields
    /// are unencrypted. Checks if `recipient` matches `ivk`, constructs the
    /// protocol note, computes its cmx, and returns the result.
    #[allow(clippy::too_many_arguments)]
    fn try_decrypt_issuance(
        _network: &Network,
        _account: u32,
        _scope: u8,
        _ivk: &Self::IVK,
        _height: u32,
        _ivtx: u32,
        _vout: u32,
        _issue_note: &CompactIssueNote,
        _asset_base: &AssetBase,
    ) -> Result<Option<(Self::Note, Note)>> {
        Ok(None) // default: no issuance support
    }

    /// Compute the note commitment (cmx) for a plaintext issuance note.
    /// This is independent of wallet keys — used for tree building for all
    /// issuance notes, including ones we don't own.
    /// Returns `Ok(None)` for protocols that don't support issuance;
    /// `Ok(Some(cmx))` on success; `Err` only on malformed data.
    fn compute_issuance_cmx(
        _issue_note: &CompactIssueNote,
        _asset_base: &AssetBase,
    ) -> Result<Option<Hash32>> {
        Ok(None) // default: issuance not supported
    }
}

/// Outputs per batch: enough to amortise the batched inversions, small enough to keep every core busy.
const DECRYPT_BATCH: usize = 64;

/// Every note of `blocks` that belongs to one of `keys`, with that key's nullifier key, in output order.
fn decrypt_outputs<'k, P: ShieldedProtocol>(
    network: &Network,
    keys: &'k [(u32, u8, P::IVK, P::NK)],
    blocks: &[CompactBlock],
) -> Vec<(P::Note, Note, &'k P::NK)> {
    // A pool without keys still syncs its tree: skip preparing epks nobody decrypts with.
    if keys.is_empty() {
        return Vec::new();
    }
    let outputs: Vec<OutputRef<P::Output>> = blocks
        .iter()
        .flat_map(|b| {
            b.vtx.iter().enumerate().flat_map(move |(ivtx, vtx)| {
                P::extract_outputs(vtx)
                    .iter()
                    .enumerate()
                    .map(move |(vout, o)| (b.height as u32, ivtx as u32, vout as u32, o))
            })
        })
        .collect();
    let ivks: Vec<_> = keys.iter().map(|(a, s, ivk, _)| (*a, *s, ivk)).collect();
    outputs
        .par_chunks(DECRYPT_BATCH)
        .flat_map_iter(|chunk| {
            P::try_decrypt_batch(network, &ivks, chunk)
                .into_iter()
                .map(|(k, n, dbn)| (n, dbn, &keys[k].3))
        })
        .collect()
}

/// Leaves of a subtree, as `GetSubtreeRoots` counts them: 2^16.
pub const SUBTREE_DEPTH: usize = 16;
/// One subtree in this many is hashed even when it could be grafted, and its root checked.
const VERIFY_EVERY: u64 = 16;

/// The server's completed subtrees of a pool: `roots[i]` is subtree `first + i`.
#[derive(Debug, Default, Clone)]
pub struct SubtreeRoots {
    pub first: u32,
    pub roots: Vec<CompletedSubtree>,
}

impl SubtreeRoots {
    /// The roots of the subtrees whose last leaf is in this batch, each kept only when the server
    /// names the block that holds that leaf: a root from another chain or another index is never used.
    fn bound(
        &self,
        first: u32,
        block_ends: &[(u64, &CompactBlock)],
        depth: usize,
    ) -> HashMap<u64, Hash32> {
        let size = 1u64 << depth;
        let end = block_ends.last().map_or(0, |(end, _)| *end);
        let mut bound = HashMap::new();
        let mut k = u64::from(first) >> depth;
        while (k + 1) * size <= end {
            let last_leaf = (k + 1) * size - 1;
            let block = block_ends[block_ends.partition_point(|(end, _)| *end <= last_leaf)].1;
            let served = k
                .checked_sub(u64::from(self.first))
                .and_then(|i| self.roots.get(i as usize));
            if let Some(served) = served.filter(|served| {
                u64::from(served.height) == block.height && block.hash == served.block_hash()
            }) {
                bound.insert(k, served.root);
            }
            k += 1;
        }
        bound
    }
}

/// The batch's leaves in tree order (each transaction's outputs, then the notes it issued) and,
/// per block, the tree position after its last leaf.
fn batch_leaves<'b, P: ShieldedProtocol>(
    blocks: &'b [CompactBlock],
    issuance_cmxs: &[(u32, u32, Vec<Hash32>)],
    first: u32,
) -> (Vec<Hash32>, Vec<(u64, &'b CompactBlock)>) {
    let issued: HashMap<(u32, u32), &[Hash32]> = issuance_cmxs
        .iter()
        .map(|(h, i, c)| ((*h, *i), c.as_slice()))
        .collect();
    let mut leaves = vec![];
    let mut block_ends = vec![];
    for cb in blocks {
        for (ivtx, vtx) in cb.vtx.iter().enumerate() {
            leaves.extend(P::extract_outputs(vtx).iter().map(P::extract_cmx));
            if let Some(cmxs) = issued.get(&(cb.height as u32, ivtx as u32)) {
                leaves.extend_from_slice(cmxs);
            }
        }
        block_ends.push((u64::from(first) + leaves.len() as u64, cb));
    }
    (leaves, block_ends)
}

#[derive(Debug)]
pub struct Synchronizer<P: ShieldedProtocol> {
    pub hasher: P::Hasher,
    pub network: Network,
    pub pool: u8,
    pub keys: Vec<(u32, u8, P::IVK, P::NK)>,
    pub position: u32,
    pub utxos: HashMap<Vec<u8>, UTXO>,
    pub tree_state: Edge,
    pub tx_decrypted: Sender<WarpSyncMessage>,
    /// Roots of completed subtrees, grafted in place of hashing them.
    pub subtree_roots: SubtreeRoots,
    /// Leaves after `position` not hashed yet (see `Tree::pending`).
    pending: Vec<Hash32>,
    pub _data: PhantomData<P>,
}

impl<P: ShieldedProtocol> Synchronizer<P> {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        network: Network,
        connection: &mut SqliteConnection,
        pool: u8,
        height: u32,
        accounts: &[(u32, bool)],
        tx_decrypted: Sender<WarpSyncMessage>,
        position: u32,
        tree_state: Edge,
    ) -> Result<Self> {
        let mut keys = vec![];
        for (id, use_internal) in accounts.iter() {
            if let Some((ivk, nk)) = P::extract_ivk(&mut *connection, *id, 0).await? {
                keys.push((*id, 0u8, ivk, nk));
            }
            if *use_internal {
                if let Some((ivk, nk)) = P::extract_ivk(&mut *connection, *id, 1).await? {
                    keys.push((*id, 1u8, ivk, nk));
                }
            }
        }

        let mut utxos: HashMap<Vec<u8>, UTXO> = HashMap::new();

        for (account, _, _, _) in keys.iter() {
            debug!(
                "fetch UTXOs - account: {}, pool: {}, height: {}",
                account, pool, height
            );
            let mut nfs = sqlx::query(
                r"
            WITH unspent AS (SELECT a.*
                FROM notes a
                LEFT JOIN spends b ON a.id_note = b.id_note
                WHERE b.id_note IS NULL)
            SELECT u.id_note, u.account, position, nullifier, value, cmx, witness FROM unspent u
            JOIN witnesses w
                ON u.id_note = w.note
                WHERE pool = ? AND u.account = ? AND w.height = ?",
            )
            .bind(pool)
            .bind(account)
            .bind(height - 1)
            .fetch(&mut *connection);
            while let Some(row) = nfs.try_next().await? {
                let id_note = row.get::<u32, _>(0);
                let account = row.get::<u32, _>(1);
                let position = row.get::<u32, _>(2);
                let nullifier = row.get::<Vec<u8>, _>(3);
                let value = row.get::<i64, _>(4) as u64;
                let cmx = row.get::<Vec<u8>, _>(5);
                let witness = row.get::<Vec<u8>, _>(6);
                let (witness, _) = bincode::decode_from_slice(&witness, legacy()).unwrap();
                let utxo = UTXO {
                    id: id_note,
                    pool,
                    account,
                    nullifier,
                    position,
                    value,
                    cmx,
                    witness,
                    ..UTXO::default()
                };

                let mut key = account.to_be_bytes().to_vec();
                key.extend_from_slice(&utxo.nullifier);
                utxos.insert(key, utxo);
            }
        }

        Ok(Self {
            hasher: P::Hasher::default(),
            network,
            pool,
            keys,
            position,
            utxos,
            tree_state,
            tx_decrypted,
            subtree_roots: SubtreeRoots::default(),
            pending: vec![],
            _data: Default::default(),
        })
    }

    pub fn has_no_keys(&self) -> bool {
        self.keys.is_empty()
    }

    pub async fn add(&mut self, blocks: &[CompactBlock]) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }

        let network = self.network;
        let mut notes = decrypt_outputs::<P>(&network, &self.keys, blocks);

        // Process issuance notes from vtx.issuances — plaintext, no trial
        // decryption needed.  Per tx we track the cmxs (for tree building)
        // and the total count (for position tracking).  Only the Orchard
        // protocol supports ZSA issuance (gated by supports_issuance()).
        let mut issuance_cmxs: Vec<(u32, u32, Vec<[u8; 32]>)> = Vec::new();
        for cb in blocks.iter() {
            for (ivtx, tx) in cb.vtx.iter().enumerate() {
                let height = cb.height as u32;
                let actions_len = P::extract_outputs(tx).len() as u32;
                let mut tx_issuance_cmxs: Vec<[u8; 32]> = Vec::new();
                let mut note_vout = actions_len;

                for iss in &tx.issuances {
                    let desc_hash: [u8; 32] = iss
                        .asset_desc_hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid asset_desc_hash length"))?;
                    let ik = IssueValidatingKey::<ZSASchnorr>::decode(&iss.ik)
                        .map_err(|e| anyhow::anyhow!("Invalid issuer key: {e}"))?;
                    let asset_id = AssetId::new_v0(&ik, &desc_hash);
                    let asset_base = AssetBase::custom(&asset_id);

                    for note in &iss.notes {
                        // Compute cmx for tree building. Returns None for
                        // protocols that don't support issuance (Sapling, Ironwood).
                        if let Some(cmx) = P::compute_issuance_cmx(note, &asset_base)? {
                            tx_issuance_cmxs.push(cmx);
                        }

                        // Check if this note belongs to any of our wallet keys.
                        for (account, scope, ivk, nk) in &self.keys {
                            if let Some((n, dbn)) = P::try_decrypt_issuance(
                                &network,
                                *account,
                                *scope,
                                ivk,
                                height,
                                ivtx as u32,
                                note_vout,
                                note,
                                &asset_base,
                            )
                            .unwrap_or_else(|e| {
                                tracing::warn!("issuance decrypt error: {e}");
                                None
                            }) {
                                notes.push((n, dbn, nk));
                            }
                        }
                        note_vout += 1;
                    }
                }

                if !tx_issuance_cmxs.is_empty() {
                    issuance_cmxs.push((height, ivtx as u32, tx_issuance_cmxs));
                }
            }
        }

        // Build a lookup of per-tx issuance note counts for position tracking.
        let mut issuance_count: std::collections::HashMap<(u32, u32), u32> =
            std::collections::HashMap::new();
        for (height, ivtx, cmxs) in &issuance_cmxs {
            issuance_count.insert((*height, *ivtx), cmxs.len() as u32);
        }

        // Sort by (height, ivtx, vout) so issuance notes are interleaved
        // with action notes within the same transaction. Without this sort,
        // issuance notes appended after all action notes would never be
        // reached by the block-iteration note_iterator below.
        notes.sort_by(|(_, a, _), (_, b, _)| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.ivtx.cmp(&b.ivtx))
                .then_with(|| a.vout.cmp(&b.vout))
        });

        let mut note_iterator = notes.iter_mut();
        let mut note = note_iterator.next();

        // Leaves in the tree so far, those waiting to be hashed included.
        let first_leaf = self.position + self.pending.len() as u32;
        let mut position = first_leaf;
        let mut height = 0;
        for cb in blocks.iter() {
            height = cb.height as u32;
            for (ivtx, tx) in cb.vtx.iter().enumerate() {
                loop {
                    match note {
                        Some((n, dbn, nk))
                            if dbn.height == cb.height as u32 && dbn.ivtx == ivtx as u32 =>
                        {
                            dbn.position = position + dbn.vout;
                            let nf = P::derive_nf(nk, dbn.position, n)?;
                            dbn.nf = nf.to_vec();

                            let transaction = Transaction {
                                account: dbn.account,
                                height: cb.height as u32,
                                time: cb.time,
                                txid: (*tx.hash).into(),
                                ..Transaction::default()
                            };
                            self.tx_decrypted
                                .send(WarpSyncMessage::Transaction(transaction))
                                .await
                                .context("sending transaction")?;

                            dbn.txid = tx.hash.clone();
                            self.tx_decrypted
                                .send(WarpSyncMessage::Note(dbn.clone()))
                                .await
                                .context("sending note")?;
                            note = note_iterator.next();
                        }
                        _ => break,
                    }
                }
                let extra = issuance_count
                    .get(&(cb.height as u32, ivtx as u32))
                    .copied()
                    .unwrap_or(0);
                position += P::extract_outputs(tx).len() as u32 + extra;
            }
        }

        let new_utxos = notes
            .into_iter()
            .map(|(_, dbn, _)| UTXO {
                id: dbn.id,
                account: dbn.account,
                pool: self.pool,
                position: dbn.position,
                nullifier: dbn.nf.to_vec(),
                value: dbn.value,
                cmx: dbn.cmx.clone(),
                witness: Witness::default(),
                ..UTXO::default()
            })
            .collect::<Vec<_>>();

        let (leaves, block_ends) = batch_leaves::<P>(blocks, &issuance_cmxs, first_leaf);
        let roots = self
            .subtree_roots
            .bound(first_leaf, &block_ends, SUBTREE_DEPTH);
        tracing::debug!("Old notes #{}", self.utxos.len());
        tracing::debug!("New notes #{}", new_utxos.len());
        let debug = enabled!(target: "warp", tracing::Level::DEBUG);
        let mut tree = Tree {
            hasher: &self.hasher,
            position: &mut self.position,
            edge: &mut self.tree_state,
            pending: &mut self.pending,
            utxos: &mut self.utxos,
        };
        tree.add_leaves(&leaves, new_utxos, &roots, SUBTREE_DEPTH)?;
        if debug {
            // The anchor check below needs the edge up to date.
            tree.flush(&roots, SUBTREE_DEPTH)?;
        }
        // Only the DEBUG anchor check reads the auth path, and it costs a tree walk per chunk.
        let auth_path = debug.then(|| self.tree_state.to_auth_path(&self.hasher));
        let mut root: Option<[u8; 32]> = None;
        for utxo in self.utxos.values_mut() {
            if let Some(auth_path) = &auth_path {
                let w = &mut utxo.witness;
                let anchor = w.root(&auth_path.0, &self.hasher);
                w.anchor = anchor;
                if let Some(root) = root {
                    if root != anchor {
                        tracing::error!("Anchor mismatch for UTXO {utxo:?}");
                    }
                } else {
                    root = Some(anchor);
                }
            }
            self.tx_decrypted
                .send(WarpSyncMessage::Witness(
                    utxo.account,
                    height,
                    utxo.cmx.clone(),
                    utxo.witness.clone(),
                ))
                .await
                .context("sending witness")?;
        }
        let accounts = self
            .keys
            .iter()
            .map(|(account, _, _, _)| *account)
            .collect::<Vec<_>>();

        for cb in blocks.iter() {
            for vtx in cb.vtx.iter() {
                for sp in P::extract_inputs(vtx).iter() {
                    let nf = P::extract_nf(sp);
                    let nf = nf.as_slice();
                    for account in accounts.iter() {
                        let mut key = account.to_be_bytes().to_vec();
                        key.extend_from_slice(nf);

                        if let Some(mut utxo) = self.utxos.remove(&key) {
                            utxo.txid = vtx.hash.clone();
                            let tx = Transaction {
                                account: utxo.account,
                                height: cb.height as u32,
                                time: cb.time,
                                txid: (*vtx.hash).into(),
                                ..Transaction::default()
                            };
                            self.tx_decrypted
                                .send(WarpSyncMessage::Transaction(tx))
                                .await
                                .context("sending transaction")?;
                            self.tx_decrypted
                                .send(WarpSyncMessage::Spend(utxo))
                                .await
                                .context("sending spend")?;
                        }
                    }
                }
            }
        }
        self.tx_decrypted
            .send(WarpSyncMessage::Checkpoint(accounts, self.pool, height))
            .await
            .context("sending checkpoint")?;

        Ok(())
    }
}

/// A pool's note commitment tree as the scan keeps it: the leaves hashed so far, the edge (the left
/// nodes still waiting for a right sibling), the leaves after them not hashed yet, and the unspent
/// notes with their witnesses.
struct Tree<'a, H: Hasher> {
    hasher: &'a H,
    /// Leaves hashed; the edge is the tree's as of this one.
    position: &'a mut u32,
    edge: &'a mut Edge,
    /// The leaves after `position`, all in one subtree that is not complete and holds no note:
    /// hashed or grafted once it completes. Only the edge lags meanwhile; no witness takes
    /// anything from an incomplete subtree, and spends build their paths from the server's tree.
    pending: &'a mut Vec<Hash32>,
    utxos: &'a mut HashMap<Vec<u8>, UTXO>,
}

impl<H: Hasher> Tree<'_, H> {
    /// Appends a batch's leaves, with the notes found among them. A complete subtree of
    /// `2^subtree_depth` leaves that holds no unspent note and has a root in `roots` is grafted:
    /// the root is appended in its place. Every `VERIFY_EVERY`th subtree is hashed regardless.
    fn add_leaves(
        &mut self,
        leaves: &[Hash32],
        mut new_utxos: Vec<UTXO>,
        roots: &HashMap<u64, Hash32>,
        subtree_depth: usize,
    ) -> Result<()> {
        let mut all = std::mem::take(self.pending);
        all.extend_from_slice(leaves);
        let leaves = all;
        let start = u64::from(*self.position);
        let end = start + leaves.len() as u64;
        let size = 1u64 << subtree_depth;
        let noted: HashSet<u64> = self
            .utxos
            .values()
            .chain(new_utxos.iter())
            .map(|utxo| u64::from(utxo.position) >> subtree_depth)
            .collect();
        let graftable = |k: u64| {
            (k + 1) * size <= end
                && !noted.contains(&k)
                && k % VERIFY_EVERY != 0
                && roots.contains_key(&k)
        };
        // The last subtree, not complete, waits while no note is in it.
        let waits = |k: u64| (k + 1) * size > end && !noted.contains(&k);
        new_utxos.sort_by_key(|utxo| utxo.position);
        let mut new_utxos = new_utxos.into_iter().peekable();
        let mut at = start;
        while at < end {
            let first = at >> subtree_depth;
            let mut k = first;
            if graftable(k) {
                let mut layer = vec![];
                while k * size < end && graftable(k) {
                    layer.push(roots.get(&k).copied());
                    k += 1;
                }
                // The edge below the subtree level is inside the first subtree, which its root replaces.
                self.edge.0[..subtree_depth].fill(None);
                *self.position = (first * size) as u32;
                self.append_layer(subtree_depth, layer, vec![], None)?;
                at = k * size;
            } else if waits(k) {
                self.pending
                    .extend_from_slice(&leaves[(at - start) as usize..]);
                at = end;
            } else {
                while k * size < end && !graftable(k) && !waits(k) {
                    k += 1;
                }
                let to = (k * size).min(end);
                let layer = leaves[(at - start) as usize..(to - start) as usize]
                    .iter()
                    .map(|leaf| Some(*leaf))
                    .collect();
                let mut found = vec![];
                while new_utxos
                    .peek()
                    .is_some_and(|utxo| u64::from(utxo.position) < to)
                {
                    found.extend(new_utxos.next());
                }
                self.append_layer(0, layer, found, Some((roots, subtree_depth)))?;
                at = to;
            }
        }
        anyhow::ensure!(
            new_utxos.next().is_none(),
            "a note outside the batch's leaves"
        );
        Ok(())
    }

    /// Hashes the leaves waiting, bringing the edge up to date.
    fn flush(&mut self, roots: &HashMap<u64, Hash32>, subtree_depth: usize) -> Result<()> {
        let pending = std::mem::take(self.pending);
        if pending.is_empty() {
            return Ok(());
        }
        let layer = pending.into_iter().map(Some).collect();
        self.append_layer(0, layer, vec![], Some((roots, subtree_depth)))
    }

    /// Appends `cmxs`, consecutive nodes at `depth0` starting where the tree is, and hashes them up
    /// to the root, updating the new notes' witnesses, the older notes' missing ommers and the edge.
    /// Subtree roots met at `check`'s depth must equal the server's.
    fn append_layer(
        &mut self,
        depth0: usize,
        mut cmxs: Vec<Option<Hash32>>,
        mut new_utxos: Vec<UTXO>,
        check: Option<(&HashMap<u64, Hash32>, usize)>,
    ) -> Result<()> {
        let count = cmxs.len() as u32;
        for depth in depth0..MERKLE_DEPTH as usize {
            let mut position = *self.position >> depth;
            if position % 2 == 1 {
                cmxs.insert(0, Some(self.edge.0[depth].unwrap()));
                position -= 1;
            }

            if let Some((roots, subtree_depth)) = check {
                if depth == subtree_depth {
                    // A node taken from the edge was checked, or grafted, before.
                    let from_edge = usize::from(*self.position >> depth != position);
                    for (i, node) in cmxs.iter().enumerate().skip(from_edge) {
                        let index = u64::from(position) + i as u64;
                        if let (Some(node), Some(root)) = (node, roots.get(&index)) {
                            anyhow::ensure!(
                                node == root,
                                "the server's root of subtree {index} is not the one hashed"
                            );
                        }
                    }
                }
            }

            for n in new_utxos.iter_mut() {
                let npos = n.position >> depth;
                let nidx = (npos - position) as usize;

                if depth == 0 {
                    n.witness.position = npos;
                    n.witness.value = cmxs[nidx].unwrap();
                }

                if nidx.is_multiple_of(2) {
                    if nidx + 1 < cmxs.len() {
                        assert!(
                            cmxs[nidx + 1].is_some(),
                            "{} {} {}",
                            depth,
                            n.position,
                            nidx
                        );
                        n.witness.ommers.0[depth] = cmxs[nidx + 1];
                    } else {
                        n.witness.ommers.0[depth] = None;
                    }
                } else {
                    assert!(
                        cmxs[nidx - 1].is_some(),
                        "{} {} {}",
                        depth,
                        n.position,
                        nidx
                    );
                    n.witness.ommers.0[depth] = cmxs[nidx - 1];
                }
            }

            let len = cmxs.len();
            if len >= 2 {
                for n in self.utxos.values_mut() {
                    if n.witness.ommers.0[depth].is_none() {
                        assert!(cmxs[1].is_some());
                        n.witness.ommers.0[depth] = cmxs[1];
                    }
                }
            }

            if len % 2 == 1 {
                self.edge.0[depth] = cmxs[len - 1];
            } else {
                self.edge.0[depth] = None;
            }

            let pairs = len / 2;
            cmxs = self.hasher.parallel_combine_opt(depth as u8, &cmxs, pairs);
        }
        *self.position += count << depth0;
        for utxo in new_utxos {
            let mut key = utxo.account.to_be_bytes().to_vec();
            key.extend_from_slice(&utxo.nullifier);
            self.utxos.insert(key, utxo);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::orchard::OrchardProtocol;
    use super::sapling::SaplingProtocol;
    use super::*;
    use crate::warp::decrypter::tests::{
        fields, orchard_action, orchard_fvk, orchard_ivk, orchard_scalar, sapling_dfvk,
        sapling_output, sapling_scalar, Bytes, NoteFields, OrchardKind, ORCHARD_HEIGHT,
    };

    type Scalar<P> = fn(
        &Network,
        &[(u32, u8, &<P as ShieldedProtocol>::IVK)],
        &[OutputRef<<P as ShieldedProtocol>::Output>],
    ) -> Vec<(usize, <P as ShieldedProtocol>::Note, Note)>;

    /// The caller before batching: every output, one call, no chunks.
    fn decrypt_unchunked<P: ShieldedProtocol>(
        keys: &[(u32, u8, P::IVK, P::NK)],
        blocks: &[CompactBlock],
        scalar: Scalar<P>,
    ) -> Vec<(NoteFields, usize)> {
        let mut outputs = vec![];
        for b in blocks {
            for (ivtx, tx) in b.vtx.iter().enumerate() {
                for (vout, o) in P::extract_outputs(tx).iter().enumerate() {
                    outputs.push((b.height as u32, ivtx as u32, vout as u32, o));
                }
            }
        }
        let ivks: Vec<_> = keys.iter().map(|(a, s, ivk, _)| (*a, *s, ivk)).collect();
        scalar(&Network::Main, &ivks, &outputs)
            .iter()
            .map(|(k, _, dbn)| (fields(dbn), *k))
            .collect()
    }

    fn decrypted<P: ShieldedProtocol>(
        keys: &[(u32, u8, P::IVK, P::NK)],
        blocks: &[CompactBlock],
    ) -> Vec<(NoteFields, usize)> {
        decrypt_outputs::<P>(&Network::Main, keys, blocks)
            .iter()
            .map(|(_, dbn, nk)| {
                let k = keys
                    .iter()
                    .position(|key| std::ptr::eq(&key.3, *nk))
                    .unwrap();
                (fields(dbn), k)
            })
            .collect()
    }

    /// Blocks of single-output txs, `outputs[i]` replaced by `ours[i]` where given.
    fn blocks<O: Clone>(
        height: u32,
        filler: &O,
        ours: &[(usize, O)],
        total: usize,
        tx: fn(O) -> CompactTx,
    ) -> Vec<CompactBlock> {
        let per_block = 50;
        (0..total.div_ceil(per_block))
            .map(|b| CompactBlock {
                height: (height + b as u32) as u64,
                vtx: (b * per_block..((b + 1) * per_block).min(total))
                    .map(|i| {
                        let o = ours
                            .iter()
                            .find(|(at, _)| *at == i)
                            .map_or(filler, |(_, o)| o);
                        tx(o.clone())
                    })
                    .collect(),
                ..Default::default()
            })
            .collect()
    }

    /// Matches on both sides of each chunk boundary, at the ends, and on every key.
    const AT: [usize; 7] = [0, B - 1, B, B + 1, 2 * B - 1, 2 * B, TOTAL - 1];
    const B: usize = DECRYPT_BATCH;
    const TOTAL: usize = 300;
    const _: () = assert!(TOTAL > 2 * B + 1);

    #[test]
    fn decrypt_outputs_orchard_across_chunks_matches_unchunked_scalar_path() {
        let mut bytes = Bytes::new(5);
        let (a, b) = (orchard_fvk(1), orchard_fvk(2));
        let keys = vec![
            (1, 0, orchard_ivk(&a, 0), a.clone()),
            (1, 1, orchard_ivk(&a, 1), a.clone()),
            (2, 0, orchard_ivk(&b, 0), b.clone()),
            (3, 0, orchard_ivk(&a, 0), a.clone()),
        ];
        let kinds = [OrchardKind::V2, OrchardKind::Ironwood, OrchardKind::Zsa];
        let ours: Vec<_> = AT
            .iter()
            .enumerate()
            .map(|(i, &at)| {
                let (fvk, scope) = [(&a, 0), (&a, 1), (&b, 0)][i % 3];
                (
                    at,
                    orchard_action(fvk, scope, 100 + i as u64, kinds[i % 3], &mut bytes),
                )
            })
            .collect();
        let filler = orchard_action(&orchard_fvk(9), 0, 1, OrchardKind::V2, &mut bytes);
        let blocks = blocks(ORCHARD_HEIGHT, &filler, &ours, TOTAL, |a| CompactTx {
            actions: vec![a],
            ..Default::default()
        });

        let notes = decrypted::<OrchardProtocol>(&keys, &blocks);

        let keys_hit: Vec<usize> = notes.iter().map(|(_, k)| *k).collect();
        assert_eq!(keys_hit, [0, 3, 1, 2, 0, 3, 1, 2, 0, 3]);
        assert_eq!(
            notes,
            decrypt_unchunked::<OrchardProtocol>(&keys, &blocks, orchard_scalar)
        );
    }

    #[test]
    fn decrypt_outputs_sapling_across_chunks_matches_unchunked_scalar_path() {
        let mut bytes = Bytes::new(6);
        let (a, b) = (sapling_dfvk(1), sapling_dfvk(2));
        let key = |account, scope, dfvk| {
            let (ivk, nk) = crate::keys::sapling_ivk_nk_for_scope(scope, dfvk);
            (account, scope, ivk, nk)
        };
        let keys = vec![key(1, 0u8, &a), key(1, 1, &a), key(2, 0, &b), key(3, 0, &a)];
        let ours: Vec<_> = AT
            .iter()
            .enumerate()
            .map(|(i, &at)| {
                let (dfvk, scope) = [(&a, 0), (&a, 1), (&b, 0)][i % 3];
                (
                    at,
                    sapling_output(dfvk, scope, 100 + i as u64, true, &mut bytes),
                )
            })
            .collect();
        let filler = sapling_output(&sapling_dfvk(9), 0, 1, true, &mut bytes);
        let blocks = blocks(ORCHARD_HEIGHT, &filler, &ours, TOTAL, |o| CompactTx {
            outputs: vec![o],
            ..Default::default()
        });

        let notes = decrypted::<SaplingProtocol>(&keys, &blocks);

        let keys_hit: Vec<usize> = notes.iter().map(|(_, k)| *k).collect();
        assert_eq!(keys_hit, [0, 3, 1, 2, 0, 3, 1, 2, 0, 3]);
        assert_eq!(
            notes,
            decrypt_unchunked::<SaplingProtocol>(&keys, &blocks, sapling_scalar)
        );
    }
}

#[cfg(test)]
mod graft_tests {
    use super::orchard::OrchardProtocol;
    use super::*;
    use crate::lwd::CompactOrchardAction;
    use crate::warp::decrypter::tests::{
        orchard_action, orchard_fvk, orchard_ivk, Bytes, OrchardKind, ORCHARD_HEIGHT,
    };
    use crate::warp::hasher::{empty_roots, OrchardHasher};

    /// Subtrees of 8 leaves, so that many fit in a test.
    const DEPTH: usize = 3;

    /// A leaf that is a valid field element.
    fn leaf(i: u32) -> Hash32 {
        let mut leaf = [0u8; 32];
        leaf[..4].copy_from_slice(&i.to_le_bytes());
        leaf[4] = 7;
        leaf
    }

    fn note(position: u32) -> UTXO {
        UTXO {
            account: 1,
            position,
            nullifier: position.to_be_bytes().to_vec(),
            ..UTXO::default()
        }
    }

    /// The root of `leaves` hashed level by level, empty nodes on the right: independent of `Tree`.
    fn naive_root(leaves: &[Hash32]) -> Hash32 {
        let hasher = OrchardHasher::default();
        let empty = empty_roots(&hasher);
        let mut layer = leaves.to_vec();
        for depth in 0..MERKLE_DEPTH as usize {
            if layer.len() % 2 == 1 {
                layer.push(empty.0[depth]);
            }
            layer = layer
                .chunks(2)
                .map(|pair| hasher.combine(depth as u8, &pair[0], &pair[1]))
                .collect();
        }
        layer[0]
    }

    /// `naive_root` of leaves `0..n`, `n >= 1`, computed once for every `n` a test reaches.
    fn prefix_root(n: u32) -> Hash32 {
        static ROOTS: std::sync::OnceLock<Vec<Hash32>> = std::sync::OnceLock::new();
        ROOTS.get_or_init(|| {
            let leaves: Vec<Hash32> = (0..TEST_LEAVES).map(leaf).collect();
            (1..=TEST_LEAVES as usize)
                .into_par_iter()
                .map(|n| naive_root(&leaves[..n]))
                .collect()
        })[n as usize - 1]
    }

    const TEST_LEAVES: u32 = 161;

    fn subtree_root(k: u64) -> Hash32 {
        let hasher = OrchardHasher::default();
        let size = 1u32 << DEPTH;
        let mut layer: Vec<Hash32> = (k as u32 * size..(k as u32 + 1) * size).map(leaf).collect();
        for depth in 0..DEPTH {
            layer = layer
                .chunks(2)
                .map(|pair| hasher.combine(depth as u8, &pair[0], &pair[1]))
                .collect();
        }
        layer[0]
    }

    fn all_roots(count: u64) -> HashMap<u64, Hash32> {
        (0..count).map(|k| (k, subtree_root(k))).collect()
    }

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Mode {
        /// Every leaf hashed, as before grafting: the reference.
        Hash,
        /// Grafting, the waiting leaves hashed after each batch.
        Graft,
        /// Grafting, leaves waiting for their subtree to complete.
        Wait,
    }

    struct Scan {
        position: u32,
        edge: Edge,
        utxos: HashMap<Vec<u8>, UTXO>,
    }

    impl Scan {
        fn witnesses(&self) -> Vec<(u32, Witness)> {
            let mut witnesses: Vec<_> = self
                .utxos
                .values()
                .map(|u| (u.position, u.witness.clone()))
                .collect();
            witnesses.sort_by_key(|(position, _)| *position);
            witnesses
        }

        /// Every witness and the edge give the root of all the leaves.
        fn assert_roots(&self, leaves: u32, what: &str) {
            let hasher = OrchardHasher::default();
            let root = prefix_root(leaves);
            assert_eq!(self.edge.root(&hasher), root, "{what}: edge");
            let path = self.edge.to_auth_path(&hasher).0;
            for (position, witness) in self.witnesses() {
                assert_eq!(
                    witness.root(&path, &hasher),
                    root,
                    "{what}: note at {position}"
                );
            }
        }
    }

    /// Feeds `batches` leaves at a time, with notes found at `notes` and `spent` notes (batch, position)
    /// spent after that batch: the witnesses after each batch, and the scan after a last flush.
    fn run(
        roots: &HashMap<u64, Hash32>,
        batches: &[u32],
        notes: &[u32],
        spent: &[(usize, u32)],
        mode: Mode,
    ) -> Result<(Vec<Vec<(u32, Witness)>>, Scan)> {
        let hasher = OrchardHasher::default();
        let mut scan = Scan {
            position: 0,
            edge: Edge::default(),
            utxos: HashMap::new(),
        };
        let mut pending = vec![];
        let mut after = vec![];
        let mut next = 0;
        for (batch, &n) in batches.iter().enumerate() {
            let leaves: Vec<Hash32> = (next..next + n).map(leaf).collect();
            let found = notes
                .iter()
                .filter(|p| (next..next + n).contains(*p))
                .map(|p| note(*p))
                .collect();
            next += n;
            let mut tree = Tree {
                hasher: &hasher,
                position: &mut scan.position,
                edge: &mut scan.edge,
                pending: &mut pending,
                utxos: &mut scan.utxos,
            };
            if mode == Mode::Hash {
                tree.append_layer(0, leaves.into_iter().map(Some).collect(), found, None)?;
            } else {
                tree.add_leaves(&leaves, found, roots, DEPTH)?;
            }
            if mode == Mode::Graft {
                tree.flush(roots, DEPTH)?;
            }
            assert_eq!(
                scan.position + pending.len() as u32,
                next,
                "{mode:?}: leaves lost"
            );
            if mode != Mode::Wait {
                scan.assert_roots(next, &format!("{mode:?} {batches:?} batch {batch}"));
            }
            after.push(scan.witnesses());
            for (_, position) in spent.iter().filter(|(b, _)| *b == batch) {
                scan.utxos.retain(|_, u| u.position != *position);
            }
        }
        let mut tree = Tree {
            hasher: &hasher,
            position: &mut scan.position,
            edge: &mut scan.edge,
            pending: &mut pending,
            utxos: &mut scan.utxos,
        };
        tree.flush(roots, DEPTH)?;
        scan.assert_roots(next, &format!("{mode:?} {batches:?} at the end"));
        Ok((after, scan))
    }

    /// Grafting and waiting give the reference's witnesses after every batch, and its tree at the end.
    fn assert_same_as_hashing(
        roots: &HashMap<u64, Hash32>,
        batches: &[u32],
        notes: &[u32],
        spent: &[(usize, u32)],
    ) {
        let (hashed, hashed_end) = run(roots, batches, notes, spent, Mode::Hash).unwrap();
        for mode in [Mode::Graft, Mode::Wait] {
            let (after, end) = run(roots, batches, notes, spent, mode).unwrap();
            assert_eq!(after, hashed, "{mode:?} {batches:?}");
            assert_eq!(end.position, hashed_end.position, "{mode:?} {batches:?}");
            assert_eq!(end.edge, hashed_end.edge, "{mode:?} {batches:?}");
        }
    }

    #[test]
    fn add_leaves_any_batching_matches_hashing_every_leaf() {
        // Batches ending on a subtree's last leaf, straddling and spanning subtrees, single leaves;
        // notes in a few subtrees, one found while its subtree straddles two batches.
        let notes = [2, 40, 41, 75, 130, 131];
        let mut patterns: Vec<Vec<u32>> = vec![
            vec![5, 20, 3, 30, 1, 49, 13, 40],
            vec![5, 20, 3, 4, 26, 1, 49, 12, 41],
            vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 30, 2, 2, 2, 2, 75],
            [vec![1; 40], vec![TEST_LEAVES - 40]].concat(),
            vec![TEST_LEAVES],
        ];
        let mut seed = 7u32;
        for _ in 0..10 {
            let mut batches = vec![];
            let mut total = 0;
            while total < TEST_LEAVES {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let n = ((seed >> 16) % 23 + 1).min(TEST_LEAVES - total);
                batches.push(n);
                total += n;
            }
            patterns.push(batches);
        }
        for batches in &patterns {
            assert_same_as_hashing(&all_roots(40), batches, &notes, &[]);
        }
    }

    #[test]
    fn add_leaves_note_among_waiting_leaves_matches_hashing() {
        // Subtree 1 (leaves 8..16) waits three leaves at a time; a note at 13 arrives after 11, 12 waited.
        assert_same_as_hashing(&all_roots(4), &[8, 3, 2, 3, 16], &[2, 13], &[]);
    }

    #[test]
    fn add_leaves_note_spent_mid_subtree_matches_hashing() {
        // The note at 9 keeps leaves 8..11 hashed; once spent, subtree 1 completes and is grafted from its start.
        assert_same_as_hashing(&all_roots(4), &[8, 3, 3, 10], &[2, 9], &[(1, 9)]);
    }

    #[test]
    fn add_leaves_without_roots_matches_hashing() {
        assert_same_as_hashing(&HashMap::new(), &[5, 20, 3, 30, 1, 49], &[2, 40], &[]);
    }

    #[test]
    fn add_leaves_wrong_root_of_a_hashed_subtree_fails() {
        // Subtrees 0 and 16 are always hashed, and a noted subtree too.
        for (k, notes) in [(0, vec![]), (16, vec![]), (3, vec![26])] {
            let mut roots = all_roots(20);
            roots.get_mut(&k).unwrap()[0] ^= 1;
            let error = run(&roots, &[160], &notes, &[], Mode::Wait)
                .err()
                .expect("wrong root taken");
            assert!(
                format!("{error}").contains(&format!("subtree {k} ")),
                "{error}"
            );
        }
    }

    #[test]
    fn add_leaves_wrong_root_of_a_grafted_subtree_is_taken() {
        // Content of a grafted subtree is the server's word, like the rest of its tree data.
        let mut roots = all_roots(20);
        roots.get_mut(&17).unwrap()[0] ^= 1;
        let hasher = OrchardHasher::default();
        let (mut position, mut edge, mut utxos, mut pending) =
            (0, Edge::default(), HashMap::new(), vec![]);
        let mut tree = Tree {
            hasher: &hasher,
            position: &mut position,
            edge: &mut edge,
            pending: &mut pending,
            utxos: &mut utxos,
        };
        tree.add_leaves(
            &(0..160).map(leaf).collect::<Vec<_>>(),
            vec![],
            &roots,
            DEPTH,
        )
        .unwrap();
        assert_ne!(
            edge.root(&hasher),
            naive_root(&(0..160).map(leaf).collect::<Vec<_>>())
        );
    }

    fn block(height: u64, hash: u8) -> CompactBlock {
        CompactBlock {
            height,
            hash: vec![hash; 32],
            ..Default::default()
        }
    }

    fn served(k: u64, height: u32, hash: u8) -> CompletedSubtree {
        CompletedSubtree {
            root: subtree_root(k),
            height,
            hash: [hash; 32],
        }
    }

    #[test]
    fn bound_keeps_only_roots_naming_the_block_of_the_last_leaf() {
        // Leaves 5..13 in block 100, 13..24 in block 101 (so subtree 1 ends in 101), 24..40 in 102.
        let blocks = [block(100, 0xa0), block(101, 0xa1), block(102, 0xa2)];
        let ends = vec![(13, &blocks[0]), (24, &blocks[1]), (40, &blocks[2])];
        let roots = |subtrees: Vec<CompletedSubtree>| SubtreeRoots {
            first: 0,
            roots: subtrees,
        };
        let right = roots(vec![
            served(0, 100, 0xa0),
            served(1, 101, 0xa1),
            served(2, 101, 0xa1),
            served(3, 102, 0xa2),
            served(4, 102, 0xa2),
        ]);
        let bound = right.bound(5, &ends, DEPTH);
        assert_eq!(
            bound,
            all_roots(5),
            "a subtree is checked at its last leaf's block"
        );

        let other_block = roots(vec![served(0, 100, 0xa0), served(1, 100, 0xa0)]);
        assert_eq!(
            other_block
                .bound(5, &ends, DEPTH)
                .keys()
                .collect::<Vec<_>>(),
            [&0]
        );
        let other_chain = roots(vec![served(0, 100, 0xb0)]);
        assert!(other_chain.bound(5, &ends, DEPTH).is_empty());
        let misaligned = SubtreeRoots {
            first: 1,
            roots: right.roots[1..].to_vec(),
        };
        let shifted = SubtreeRoots {
            first: 0,
            roots: right.roots[1..].to_vec(),
        };
        assert_eq!(misaligned.bound(5, &ends, DEPTH).len(), 4);
        assert!(
            shifted.bound(5, &ends, DEPTH).get(&0).is_none(),
            "an index the server ignored"
        );
    }

    #[test]
    fn bound_subtree_ending_at_a_block_boundary_takes_the_block_of_its_last_leaf() {
        // Subtree 1 (8..16) ends exactly at block 100's last leaf.
        let blocks = [block(100, 0xa0), block(101, 0xa1)];
        let ends = vec![(16, &blocks[0]), (20, &blocks[1])];
        let roots = SubtreeRoots {
            first: 1,
            roots: vec![served(1, 100, 0xa0)],
        };
        assert_eq!(roots.bound(8, &ends, DEPTH).len(), 1);
        let late = SubtreeRoots {
            first: 1,
            roots: vec![served(1, 101, 0xa1)],
        };
        assert!(late.bound(8, &ends, DEPTH).is_empty());
        // Leaf 15, the last of subtree 1, is the first of block 101.
        let ends = vec![(15, &blocks[0]), (20, &blocks[1])];
        assert_eq!(late.bound(8, &ends, DEPTH).len(), 1);
        assert!(roots.bound(8, &ends, DEPTH).is_empty());
    }

    #[test]
    fn batch_leaves_counts_issued_notes_after_their_transaction() {
        let action = |cmx: u32| CompactOrchardAction {
            cmx: leaf(cmx).to_vec(),
            ..Default::default()
        };
        let tx = |cmxs: &[u32]| CompactTx {
            actions: cmxs.iter().map(|c| action(*c)).collect(),
            ..Default::default()
        };
        let blocks = [
            CompactBlock {
                height: 10,
                vtx: vec![tx(&[1, 2]), tx(&[3])],
                ..Default::default()
            },
            CompactBlock {
                height: 11,
                vtx: vec![tx(&[6])],
                ..Default::default()
            },
        ];
        let issued = vec![(10, 0, vec![leaf(100), leaf(101)])];
        let (leaves, ends) = batch_leaves::<OrchardProtocol>(&blocks, &issued, 7);
        assert_eq!(leaves, [1, 2, 100, 101, 3, 6].map(leaf));
        let ends: Vec<_> = ends.iter().map(|(end, b)| (*end, b.height)).collect();
        assert_eq!(ends, [(12, 10), (13, 11)]);
    }

    #[tokio::test]
    async fn add_note_after_waiting_leaves_counts_them_in_its_position() {
        let mut bytes = Bytes::new(11);
        let fvk = orchard_fvk(1);
        let filler = orchard_action(&orchard_fvk(9), 0, 1, OrchardKind::V2, &mut bytes);
        let ours = orchard_action(&fvk, 0, 100, OrchardKind::V2, &mut bytes);
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let mut sync = Synchronizer::<OrchardProtocol> {
            hasher: OrchardHasher::default(),
            network: Network::Main,
            pool: 2,
            keys: vec![(1, 0, orchard_ivk(&fvk, 0), fvk.clone())],
            position: 0,
            utxos: HashMap::new(),
            tree_state: Edge::default(),
            tx_decrypted: tx,
            subtree_roots: SubtreeRoots::default(),
            pending: (0..5).map(leaf).collect(),
            _data: PhantomData,
        };
        let block = CompactBlock {
            height: ORCHARD_HEIGHT as u64,
            vtx: vec![CompactTx {
                actions: vec![filler.clone(), ours, filler],
                ..Default::default()
            }],
            ..Default::default()
        };
        sync.add(&[block]).await.unwrap();
        drop(sync.tx_decrypted);
        let mut positions = vec![];
        while let Some(message) = rx.recv().await {
            match message {
                WarpSyncMessage::Note(note) => positions.push(("note", note.position)),
                WarpSyncMessage::Witness(_, _, _, witness) => {
                    positions.push(("witness", witness.position))
                }
                _ => {}
            }
        }
        assert_eq!(positions, [("note", 6), ("witness", 6)]);
        assert_eq!(
            (sync.position, sync.pending.len()),
            (8, 0),
            "the noted subtree is hashed"
        );
    }
}
