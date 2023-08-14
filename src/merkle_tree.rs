use crate::{
    circuit_compiler::ProofData,
    pairwise_hash::PairwiseHash,
    provable::Provable,
    recursive_hash::{RecursiveHash, RecursivePairwiseHash},
    C, D, F,
};
use anyhow::Error;
use plonky2::{
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::Hasher},
};
use rayon::prelude::*;

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

        for digest in &data {
            let leaf_hash = PoseidonHash::hash_or_noop(digest);
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
        let merkle_tree_height = self.leaves.len().ilog2() as usize;
        let mut proof_datas = vec![];
        let mut current_child_hash_index = 0;
        let mut proof_data_index = 0;

        // Parallelize the inner loop using rayon
        for height in 0..(merkle_tree_height) {
            let chunk_size = 1 << (merkle_tree_height - height);

            let thread_proof_datas: Vec<_> = if height == 0 {
                (current_child_hash_index..current_child_hash_index + chunk_size)
                    .into_par_iter()
                    .step_by(2)
                    .map(|current_child_index| {
                        let pairwise_hash = PairwiseHash::new(
                            self.leaves[current_child_index].clone(),
                            self.digests[current_child_index],
                            self.leaves[current_child_index + 1].clone(),
                            self.digests[current_child_index + 1],
                        );
                        pairwise_hash.proof()
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                let inner_proof_data: Vec<_> = (current_child_hash_index
                    ..current_child_hash_index + chunk_size)
                    .into_par_iter()
                    .step_by(2)
                    .zip(
                        (proof_data_index..(proof_data_index + chunk_size))
                            .into_par_iter()
                            .step_by(2),
                    )
                    .map(|(current_child_index, proof_data_index)| {
                        let left_recursive_hash = RecursiveHash::new(
                            self.digests[current_child_index],
                            &proof_datas[proof_data_index],
                        );
                        let right_recursive_hash = RecursiveHash::new(
                            self.digests[current_child_index + 1],
                            &proof_datas[proof_data_index + 1],
                        );
                        let recursive_pairwise_hash =
                            RecursivePairwiseHash::new(left_recursive_hash, right_recursive_hash);

                        recursive_pairwise_hash.proof() // Adjust the error handling as needed
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                proof_data_index += chunk_size;

                inner_proof_data
            };

            proof_datas.extend(thread_proof_datas);
            current_child_hash_index += chunk_size;
        }

        // The last step is to connect the root of the Merkle tree with the last digest
        let mut circuit_builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let mut partial_witness = PartialWitness::<F>::new();

        let root_hash_targets = circuit_builder.add_virtual_hash();
        let last_digest_hash_targets = circuit_builder.add_virtual_hash();
        circuit_builder.connect_hashes(root_hash_targets, last_digest_hash_targets);

        partial_witness.set_hash_target(root_hash_targets, self.root);
        partial_witness.set_hash_target(last_digest_hash_targets, *self.digests.last().unwrap());

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
        ];

        let merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        assert!(merkle_tree.prove_and_verify().is_ok());
    }

    #[test]
    fn test_bigger_merkle_tree_proof_generation_2() {
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

    #[test]
    fn test_large_tree_proof_and_verification() {
        let merkle_tree_leaves = vec![vec![F::ZERO]; 16_384];
        let merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        assert!(merkle_tree.prove_and_verify().is_ok());
    }
}
