use crate::{
    circuit_compiler::{CircuitCompiler, ProofData},
    provable::Provable,
    recursive_hash::RecursiveHash,
    C, D, F,
};
use anyhow::Error;
use plonky2::{
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::Hasher},
};

// Our implementation follows the one of Plonky2:
// see https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/hash/merkle_tree.rs#L39.
pub struct MerkleTree {
    pub(crate) leaves: Vec<Vec<F>>,
    pub(crate) recursive_hashes: Vec<RecursiveHash>,
    pub(crate) root: HashOut<F>,
}

impl MerkleTree {
    pub fn create(data: Vec<Vec<F>>) -> Self {
        // A plain Merkle tree needs to have a power of two number of leaves.
        debug_assert!(data.len().is_power_of_two() && data.len() > 1);

        let merkle_tree_height = data.len().ilog2();
        let mut recursive_hashes = vec![];

        for i in (0..data.len()).step_by(2) {
            let left_leaf_hash = PoseidonHash::hash_no_pad(&data[i]);
            let right_leaf_hash = PoseidonHash::hash_no_pad(&data[i + 1]);
            recursive_hashes.push(RecursiveHash::hash_inputs(left_leaf_hash, right_leaf_hash));
        }

        let mut current_tree_height_index = 0;
        let mut i = 0;
        for height in 1..merkle_tree_height {
            while i < current_tree_height_index + (1 << (merkle_tree_height - height)) {
                let recursive_hash = RecursiveHash::hash_inputs(
                    recursive_hashes[i as usize].evaluate(),
                    recursive_hashes[i as usize + 1].evaluate(),
                );
                recursive_hashes.push(recursive_hash);
                i += 2;
            }
            current_tree_height_index += 1 << (merkle_tree_height - height);
        }

        // we assume that the number of leaves is > 1, so we should have a proper root
        let root = recursive_hashes.last().unwrap().evaluate();

        Self {
            leaves: data,
            recursive_hashes,
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
        for i in (0..self.leaves.len()).step_by(2) {
            let left_data = &self.leaves[i];
            let right_data = &self.leaves[i + 1];
            let recursive_hash = &self.recursive_hashes[i / 2];

            let left_data_targets = circuit_builder.add_virtual_targets(left_data.len());
            let right_data_targets = circuit_builder.add_virtual_targets(right_data.len());

            let left_hash_targets =
                circuit_builder.hash_n_to_hash_no_pad::<PoseidonHash>(left_data_targets.clone());
            let right_hash_targets =
                circuit_builder.hash_n_to_hash_no_pad::<PoseidonHash>(right_data_targets.clone());

            let should_be_left_hash_targets = circuit_builder.add_virtual_hash();
            let should_be_right_hash_targets = circuit_builder.add_virtual_hash();

            circuit_builder.connect_hashes(left_hash_targets, should_be_left_hash_targets);
            circuit_builder.connect_hashes(right_hash_targets, should_be_right_hash_targets);

            (0..left_data.len())
                .for_each(|i| partial_witness.set_target(left_data_targets[i], left_data[i]));
            (0..right_data.len())
                .for_each(|i| partial_witness.set_target(right_data_targets[i], right_data[i]));

            partial_witness.set_hash_target(should_be_left_hash_targets, recursive_hash.left_hash);
            partial_witness
                .set_hash_target(should_be_right_hash_targets, recursive_hash.right_hash);
        }

        // Finally, we need to link each consecutive pair of `RecursiveHash` roots
        // with the leaves of its parent `RecursiveHash`
        let merkle_tree_height = self.leaves.len().ilog2() as usize;
        let mut current_tree_height_index = 0;
        let mut i = 0;
        for height in 1..merkle_tree_height {
            while i < current_tree_height_index + (1 << (merkle_tree_height - height)) {
                let left_child_root_hash_targets = circuit_builder.add_virtual_hash();
                let right_child_root_hash_targets = circuit_builder.add_virtual_hash();

                let left_child_hash_targets = circuit_builder.add_virtual_hash();
                let right_child_hash_targets = circuit_builder.add_virtual_hash();

                circuit_builder
                    .connect_hashes(left_child_root_hash_targets, left_child_hash_targets);
                circuit_builder
                    .connect_hashes(right_child_root_hash_targets, right_child_hash_targets);

                partial_witness.set_hash_target(
                    left_child_root_hash_targets,
                    self.recursive_hashes[i].evaluate(),
                );
                partial_witness.set_hash_target(
                    right_child_root_hash_targets,
                    self.recursive_hashes[i + 1].evaluate(),
                );

                partial_witness.set_hash_target(
                    left_child_hash_targets,
                    self.recursive_hashes[i + (1 << (merkle_tree_height - height))].left_hash,
                );
                partial_witness.set_hash_target(
                    right_child_hash_targets,
                    self.recursive_hashes[i + (1 << (merkle_tree_height - height))].right_hash,
                );

                i += 2;
            }
            current_tree_height_index += 1 << (merkle_tree_height - height);
        }

        // Recursive proof verification of the
        // NOTE: we can parallelize the process of generating the recursive proofs for each
        // [`RecursiveHash`]
        for recursive_hash in self.recursive_hashes {
            let proof_data = recursive_hash.proof()?;
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
    // Compares a
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
    fn test_proof_generation_fails_for_invalid_recursive_hashes() {
        let f_one: F = F::ONE;
        let f_two: F = F::from_canonical_u64(2);
        let f_three: F = F::from_canonical_u64(3);
        let f_four: F = F::from_canonical_u64(4);

        let merkle_tree_leaves = vec![vec![f_one], vec![f_two], vec![f_three], vec![f_four]];

        let mut merkle_tree = MerkleTree::create(merkle_tree_leaves.clone());
        merkle_tree.recursive_hashes[2] = RecursiveHash::new_from_data(
            &[F::from_canonical_u64(128)],
            &[F::from_canonical_u64(256)],
        );
        assert!(merkle_tree.prove_and_verify().is_err());
    }
}
