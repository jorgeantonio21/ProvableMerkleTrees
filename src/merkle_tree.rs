use crate::{
    circuit_compiler::ProofData, pairwise_hash::PairwiseHash, provable::Provable, C, D, F,
};
use anyhow::Error;
use plonky2::{
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::Hasher},
};

// Our implementation is inspired by the one of Plonky2:
// see https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/hash/merkle_tree.rs#L39.
pub struct MerkleTree {
    pub(crate) leaves: Vec<Vec<F>>,
    pub(crate) digests: Vec<HashOut<F>>,
    pub(crate) root: HashOut<F>,
}

impl MerkleTree {
    pub fn create(data: Vec<Vec<F>>) -> Self {
        // A plain Merkle tree needs to have a power of two number of leaves.
        debug_assert!(data.len().is_power_of_two() && data.len() > 1);

        let merkle_tree_height = data.len().ilog2();
        let mut digests = vec![];

        for i in 0..data.len() {
            let leaf_hash = PoseidonHash::hash_or_noop(&data[i]);
            digests.push(leaf_hash);
        }

        let mut current_tree_height_index = 0;
        let mut i = 0;
        for height in 0..merkle_tree_height {
            while i < current_tree_height_index + (1 << (merkle_tree_height - height)) {
                let hash = PoseidonHash::hash_or_noop(
                    &[
                        digests[i as usize].elements,
                        digests[i as usize + 1].elements,
                    ]
                    .concat(),
                );
                digests.push(hash);
                i += 2;
            }
            current_tree_height_index += 1 << (merkle_tree_height - height);
        }

        // we assume that the number of leaves is > 1, so we should have a proper root
        let root = *digests.last().unwrap();

        Self {
            leaves: data,
            digests,
            root,
        }
    }
}

impl Provable<F, C, D> for MerkleTree {
    fn proof(self) -> Result<ProofData<F, C, D>, Error> {
        let config = CircuitConfig::standard_recursion_config();
        let mut circuit_builder = CircuitBuilder::<F, D>::new(config);
        let mut partial_witness = PartialWitness::<F>::new();

        // We first enforce that the hashes of the MerkleTree leaves correspond to the first recursive hashes
        for i in 0..self.leaves.len() {
            let leaf_data = &self.leaves[i];

            let leaf_data_targets = circuit_builder.add_virtual_targets(leaf_data.len());

            let leaf_hash_targets =
                circuit_builder.hash_or_noop::<PoseidonHash>(leaf_data_targets.clone());

            let should_be_leaf_hash_targets = circuit_builder.add_virtual_hash();

            circuit_builder.connect_hashes(leaf_hash_targets, should_be_leaf_hash_targets);

            (0..leaf_data.len())
                .for_each(|i| partial_witness.set_target(leaf_data_targets[i], leaf_data[i]));

            partial_witness.set_hash_target(should_be_leaf_hash_targets, self.digests[i]);
        }

        // We check that the `MerkleTree` root is well defined
        let tree_root_hash_targets = circuit_builder.add_virtual_hash();
        let should_be_tree_root_hash_targets = circuit_builder.add_virtual_hash();

        circuit_builder.connect_hashes(tree_root_hash_targets, should_be_tree_root_hash_targets);

        partial_witness.set_hash_target(tree_root_hash_targets, *self.digests.last().unwrap());
        partial_witness.set_hash_target(should_be_tree_root_hash_targets, self.root);

        // From each two consecutive pair of digests, we generate a `PairwiseHash`
        // that we later use for proof generation and verification
        let merkle_tree_height = self.leaves.len().ilog2() as usize;
        let mut pairwise_hashes = vec![];
        let mut current_tree_height_index = 0;
        let mut current_child_hash_index = 0;
        let mut parent_hash_index = 1 << merkle_tree_height;
        for height in 0..(merkle_tree_height) {
            while current_child_hash_index
                < current_tree_height_index + (1 << (merkle_tree_height - height))
            {
                let pairwise_hash = PairwiseHash::new(
                    self.digests[current_child_hash_index],
                    self.digests[current_child_hash_index + 1],
                    self.digests[parent_hash_index],
                );
                pairwise_hashes.push(pairwise_hash);
                current_child_hash_index += 2;
                parent_hash_index += 1;
            }
            current_tree_height_index += 1 << (merkle_tree_height - height);
        }

        // Recursive proof verification of the
        // NOTE: we can parallelize the process of generating the recursive proofs for each
        // [`PairwiseHash`]
        for pairwise_hash in pairwise_hashes {
            let proof_data = pairwise_hash.proof()?;
            let proof_with_pis_target =
                circuit_builder.add_virtual_proof_with_pis(&proof_data.circuit_data.common);
            let verified_data_target = circuit_builder.add_virtual_verifier_data(
                proof_data.circuit_data.common.config.fri_config.cap_height,
            );
            partial_witness
                .set_proof_with_pis_target(&proof_with_pis_target, &proof_data.proof_with_pis);
            partial_witness.set_verifier_data_target(
                &verified_data_target,
                &proof_data.circuit_data.verifier_only,
            );
        }

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data.prove(partial_witness)?;

        Ok(ProofData {
            proof_with_pis,
            circuit_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::Field;

    use super::*;

    #[test]
    // Compares our `MerkleTree` implementation with that of Plonky2
    fn test_merkle_tree() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);

        let merkle_tree_leaves = vec![vec![f_one], vec![f_two], vec![f_three], vec![f_four]];

        let merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        let should_be_merkle_tree =
            plonky2::hash::merkle_tree::MerkleTree::<F, PoseidonHash>::new(merkle_tree_leaves, 0);

        assert_eq!(merkle_tree.root, should_be_merkle_tree.cap.0[0])
    }

    #[test]
    // Tests that the proof and verification of a `MerkleTree` instance passes
    fn test_merkle_tree_generate_proof() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);

        let merkle_tree_leaves = vec![vec![f_one], vec![f_two], vec![f_three], vec![f_four]];

        let merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        assert!(merkle_tree.prove_and_verify().is_ok());
    }

    #[test]
    #[should_panic]
    // Tests that the proof and verification of a ill formed `MerkleTree` instance panics
    fn test_proof_generation_fails_for_invalid_pairwise_hashes() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);

        let merkle_tree_leaves = vec![vec![f_one], vec![f_two], vec![f_three], vec![f_four]];

        let mut merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        merkle_tree.digests[2] = PoseidonHash::hash_or_noop(&vec![F::ZERO]);
        assert!(merkle_tree.prove_and_verify().is_err());
    }

    #[test]
    #[should_panic]
    fn test_proof_generation_fails_for_invalid_data() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);

        let merkle_tree_leaves = vec![vec![f_one], vec![f_two], vec![f_three], vec![f_four]];

        let mut merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        merkle_tree.leaves[0] = vec![F::ZERO];
        assert!(merkle_tree.prove_and_verify().is_err());
    }

    #[test]
    #[should_panic]
    fn test_proof_generation_fails_for_invalid_root() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);

        let merkle_tree_leaves = vec![vec![f_one], vec![f_two], vec![f_three], vec![f_four]];

        let mut merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        merkle_tree.root = PoseidonHash::hash_or_noop(
            &[
                [F::ZERO, F::ONE, F::ZERO, F::ONE],
                [F::ONE, F::ZERO, F::ONE, F::ZERO],
            ]
            .concat(),
        );
        assert!(merkle_tree.prove_and_verify().is_err());
    }

    #[test]
    fn test_bigger_merkle_tree() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);
        let f_five: F = F::from_canonical_u64(5);
        let f_six: F = F::from_canonical_u64(6);
        let f_seven: F = F::from_canonical_u64(7);
        let f_eight: F = F::from_canonical_u64(8);

        let merkle_tree_leaves = vec![
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
        ];

        let merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        let should_be_merkle_tree =
            plonky2::hash::merkle_tree::MerkleTree::<F, PoseidonHash>::new(merkle_tree_leaves, 0);

        assert_eq!(merkle_tree.root, should_be_merkle_tree.cap.0[0])
    }

    #[test]
    fn test_bigger_merkle_tree_proof_generation() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);
        let f_five: F = F::from_canonical_u64(5);
        let f_six: F = F::from_canonical_u64(6);
        let f_seven: F = F::from_canonical_u64(7);
        let f_eight: F = F::from_canonical_u64(8);

        let merkle_tree_leaves = vec![
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
            vec![f_one],
            vec![f_two],
            vec![f_three],
            vec![f_four],
            vec![f_five],
            vec![f_six],
            vec![f_seven],
            vec![f_eight],
        ];

        let merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        assert!(merkle_tree.prove_and_verify().is_ok());
    }
}
