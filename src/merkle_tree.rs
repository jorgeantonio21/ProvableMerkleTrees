use std::hash::Hash;

use crate::{provable::CircuitCompiler, recursive_hash::RecursiveHash, D, F};
use plonky2::{
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

// Our implementation follows the one of Plonky2:
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
                let hash_targets = PoseidonHash::hash_no_pad(
                    &[
                        digests[i as usize].elements.clone(),
                        digests[i as usize + 1].elements.clone(),
                    ]
                    .concat(),
                );
                digests.push(hash_targets);
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

// // We implement a recursive proof
// impl CircuitCompiler<F, D> for MerkleTree {
//     type Value = HashOut<F>;
//     type Targets = Vec<HashOut<F>>;
//     type OutTargets = HashOut<F>;

//     fn evaluate(&self) -> Self::Value {
//         self.root.clone()
//     }

//     fn compile(
//         &self,
//         circuit_builder: &mut CircuitBuilder<F, D>,
//     ) -> (Self::Targets, Self::OutTargets) {

//     }

//     fn fill(
//         &self,
//         partial_witness: &mut PartialWitness<F>,
//         targets: Self::Targets,
//         out_targets: Self::OutTargets,
//     ) -> Result<(), anyhow::Error> {
//         Ok(())
//     }
// }

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
}
