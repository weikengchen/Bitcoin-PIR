//! PBC (Probabilistic Batch Code) cuckoo placement and multi-round planning.
//!
//! Used by both the build pipeline (assigning items to cuckoo tables) and
//! clients (planning which chunk queries go in which round).

/// Cuckoo-place item `qi` into one of its candidate groups with eviction.
/// Returns true if placed, false if `max_kicks` exceeded.
///
/// `cand_groups[qi]` must yield the candidate group indices for item `qi`.
pub fn pbc_cuckoo_place<C: AsRef<[usize]>>(
    cand_groups: &[C],
    groups: &mut [Option<usize>],
    qi: usize,
    max_kicks: usize,
    num_hashes: usize,
) -> bool {
    let cands = cand_groups[qi].as_ref();
    for &c in cands {
        if groups[c].is_none() {
            groups[c] = Some(qi);
            return true;
        }
    }

    let mut current_qi = qi;
    let mut current_group = cands[0];

    for kick in 0..max_kicks {
        let evicted_qi = groups[current_group].unwrap();
        groups[current_group] = Some(current_qi);
        let ev_cands = cand_groups[evicted_qi].as_ref();

        for offset in 0..num_hashes {
            let c = ev_cands[(kick + offset) % num_hashes];
            if c == current_group {
                continue;
            }
            if groups[c].is_none() {
                groups[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_group = ev_cands[0];
        for offset in 0..num_hashes {
            let c = ev_cands[(kick + offset) % num_hashes];
            if c != current_group {
                next_group = c;
                break;
            }
        }
        current_qi = evicted_qi;
        current_group = next_group;
    }

    false
}

/// Plan multi-round PBC placement for items with candidate groups.
/// Returns rounds, each round is a `Vec<(item_index, group_id)>`.
pub fn pbc_plan_rounds<C: AsRef<[usize]> + Clone>(
    item_groups: &[C],
    num_groups: usize,
    num_hashes: usize,
    max_kicks: usize,
) -> Vec<Vec<(usize, usize)>> {
    let mut remaining: Vec<usize> = (0..item_groups.len()).collect();
    let mut rounds = Vec::new();

    while !remaining.is_empty() {
        let round_cands: Vec<C> = remaining.iter().map(|&i| item_groups[i].clone()).collect();
        let mut group_owner: Vec<Option<usize>> = vec![None; num_groups];
        let mut placed_local = Vec::new();

        for li in 0..round_cands.len() {
            if placed_local.len() >= num_groups {
                break;
            }
            let saved = group_owner.clone();
            if pbc_cuckoo_place(&round_cands, &mut group_owner, li, max_kicks, num_hashes) {
                placed_local.push(li);
            } else {
                group_owner = saved;
            }
        }

        let mut round_entries = Vec::new();
        // `group_owner` has exactly `num_groups` entries; iterate with
        // enumerate to satisfy clippy::needless_range_loop. The loop
        // body uses `g` both to index `group_owner` and as the pushed
        // group id, so enumerate is the canonical fix.
        for (g, owner) in group_owner.iter().enumerate().take(num_groups) {
            if let Some(local_idx) = *owner {
                round_entries.push((remaining[local_idx], g));
            }
        }

        if round_entries.is_empty() {
            eprintln!(
                "PBC placement: could not place any items, {} remaining",
                remaining.len()
            );
            break;
        }

        let placed_orig: Vec<usize> = placed_local.iter().map(|&li| remaining[li]).collect();
        remaining.retain(|idx| !placed_orig.contains(idx));
        rounds.push(round_entries);
    }

    rounds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbc_cuckoo_place_simple() {
        // 3 items, 5 groups, each item has 2 candidate groups
        let cands: Vec<Vec<usize>> = vec![
            vec![0, 1],
            vec![1, 2],
            vec![2, 3],
        ];
        let mut groups = vec![None; 5];

        assert!(pbc_cuckoo_place(&cands, &mut groups, 0, 100, 2));
        assert!(pbc_cuckoo_place(&cands, &mut groups, 1, 100, 2));
        assert!(pbc_cuckoo_place(&cands, &mut groups, 2, 100, 2));

        // All items placed
        let placed: Vec<usize> = groups.iter().filter_map(|&x| x).collect();
        assert_eq!(placed.len(), 3);
    }

    #[test]
    fn test_pbc_plan_rounds() {
        // 5 items, 3 groups — needs at least 2 rounds
        let cands: Vec<Vec<usize>> = vec![
            vec![0, 1],
            vec![1, 2],
            vec![0, 2],
            vec![0, 1],
            vec![1, 2],
        ];

        let rounds = pbc_plan_rounds(&cands, 3, 2, 100);
        assert!(rounds.len() >= 2);

        // All items should be placed
        let mut all_items: Vec<usize> = rounds.iter().flat_map(|r| r.iter().map(|&(i, _)| i)).collect();
        all_items.sort();
        assert_eq!(all_items, vec![0, 1, 2, 3, 4]);
    }
}
