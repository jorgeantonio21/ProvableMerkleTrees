use anyhow::Error;
use plonky2::{
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::witness::PartialWitness,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::Hasher},
};

use crate::{
    circuit_compiler::{CircuitCompiler, ProofData},
    provable::Provable,
    C, D, F,
};

#[derive(Clone, Debug)]
/// `HashData`:
///
///     A structure representing hashed data along with its original content.
///
/// Fields:
///
///     data: A vector containing elements of type F representing the original data.
///     hash: A HashOut<F> representing the hash value of the data.
pub struct HashData {
    pub(crate) data: Vec<F>,
    pub(crate) hash: HashOut<F>,
}

impl HashData {
    /// Method `new`:
    ///
    ///     Creates a new instance of HashData.
    ///
    /// Arguments:
    ///
    ///     data: A vector containing elements of type F representing the original data.
    ///     hash: A HashOut<F> representing the hash value of the data.
    ///
    /// Returns:
    ///
    ///     Returns a HashData instance with the provided data and hash.
    pub(crate) fn new(data: Vec<F>, hash: HashOut<F>) -> Self {
        Self { data, hash }
    }
}

#[derive(Clone, Debug)]
/// `PairwiseHash`:
///
///     A structure representing a pairwise hash operation between two child nodes and their parent hash.
///
/// Fields:
///
///     left_child: A HashData instance representing the left child.
///     right_child: A HashData instance representing the right child.
///     parent_hash: A HashOut<F> representing the hash value of the parent.
pub(crate) struct PairwiseHash {
    pub(crate) left_child: HashData,
    pub(crate) right_child: HashData,
    pub(crate) parent_hash: HashOut<F>,
}

impl PairwiseHash {
    /// Method `new`:
    ///
    ///     Creates a new instance of PairwiseHash.
    ///
    /// Arguments:
    ///
    ///     left_child_data: A vector containing elements of type F representing the data of the left child.
    ///     left_child_hash: A HashOut<F> representing the hash value of the left child.
    ///     right_child_data: A vector containing elements of type F representing the data of the right child.
    ///     right_child_hash: A HashOut<F> representing the hash value of the right child.
    ///
    /// Returns:
    ///
    ///     Returns a PairwiseHash instance with the provided child data and hash values.
    pub fn new(
        left_child_data: Vec<F>,
        left_child_hash: HashOut<F>,
        right_child_data: Vec<F>,
        right_child_hash: HashOut<F>,
    ) -> Self {
        let left_child = HashData::new(left_child_data, left_child_hash);
        let right_child = HashData::new(right_child_data, right_child_hash);
        let parent_hash = PoseidonHash::hash_or_noop(
            &[left_child.hash.elements, right_child.hash.elements].concat(),
        );
        Self {
            left_child,
            right_child,
            parent_hash,
        }
    }
}

impl CircuitCompiler<F, D> for PairwiseHash {
    type Value = HashOut<F>;
    type Targets = (Vec<Target>, Vec<Target>, HashOutTarget, HashOutTarget);
    type OutTargets = HashOutTarget;

    /// `CircuitCompiler` trait method `evaluate`:
    ///  
    ///     Evaluates the pairwise hash operation and returns the resulting HashOut<F>.
    fn evaluate(&self) -> Self::Value {
        self.parent_hash
    }

    /// `CircuitCompiler` trait method `compile`:
    ///
    ///     Compiles the circuit for the pairwise hash operation.
    ///
    /// Arguments:
    ///
    ///     circuit_builder: A mutable reference to a CircuitBuilder<F, D> instance.
    ///
    /// Returns:
    ///
    ///     Returns a tuple containing targets for input data and hashes, and targets for the output hash.
    fn compile(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets) {
        let left_data_targets = circuit_builder.add_virtual_targets(self.left_child.data.len());
        let right_data_targets = circuit_builder.add_virtual_targets(self.right_child.data.len());

        let left_hash_targets = circuit_builder.add_virtual_hash();
        let right_hash_targets = circuit_builder.add_virtual_hash();

        let should_be_left_hash_targets =
            circuit_builder.hash_or_noop::<PoseidonHash>(left_data_targets.clone());
        let should_be_right_hash_targets =
            circuit_builder.hash_or_noop::<PoseidonHash>(right_data_targets.clone());

        circuit_builder.connect_hashes(should_be_left_hash_targets, left_hash_targets);
        circuit_builder.connect_hashes(should_be_right_hash_targets, right_hash_targets);

        let parent_hash_targets = circuit_builder.add_virtual_hash();

        // register public inputs
        circuit_builder.register_public_inputs(&parent_hash_targets.elements);

        let should_be_parent_hash_targets = circuit_builder.hash_or_noop::<PoseidonHash>(
            [left_hash_targets.elements, right_hash_targets.elements].concat(),
        );

        circuit_builder.connect_hashes(should_be_parent_hash_targets, parent_hash_targets);

        (
            (
                left_data_targets,
                right_data_targets,
                left_hash_targets,
                right_hash_targets,
            ),
            parent_hash_targets,
        )
    }

    /// `CircuitCompiler` trait method `fill`:
    ///
    ///     Fills the partial witness with data for the compiled circuit.
    ///
    /// Arguments:
    ///
    ///     partial_witness: A mutable reference to a PartialWitness<F> instance.
    ///     targets: A tuple containing targets for input data and hashes.
    ///     out_targets: Targets for the output hash.
    ///
    /// Returns:
    ///
    ///     Returns a Result indicating success or an error.
    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error> {
        let left_data_targets = targets.0;
        let right_data_targets = targets.1;
        let left_hash_targets = targets.2;
        let right_hash_targets = targets.3;
        let parent_hash_targets = out_targets;

        (0..left_data_targets.len()).for_each(|i| {
            partial_witness.set_target(left_data_targets[i], self.left_child.data[i])
        });
        (0..right_data_targets.len()).for_each(|i| {
            partial_witness.set_target(right_data_targets[i], self.right_child.data[i])
        });

        (0..4).for_each(|i| {
            partial_witness.set_target(
                left_hash_targets.elements[i],
                self.left_child.hash.elements[i],
            );
            partial_witness.set_target(
                right_hash_targets.elements[i],
                self.right_child.hash.elements[i],
            );
            partial_witness.set_target(
                parent_hash_targets.elements[i],
                self.parent_hash.elements[i],
            );
        });

        Ok(())
    }
}

impl Provable<F, C, D> for PairwiseHash {
    /// `Provable` trait method `proof`:
    ///
    ///     Generates a proof for the pairwise hash operation.
    ///
    /// Returns:
    ///
    ///     Returns a Result containing the generated ProofData or an Error if the proof generation fails.
    fn proof(self) -> Result<ProofData<F, C, D>, Error> {
        let config = CircuitConfig::standard_recursion_config();
        let mut circuit_builder = CircuitBuilder::new(config);
        let mut partial_witness = PartialWitness::new();

        let (targets, out_targets) = self.compile(&mut circuit_builder);
        self.fill(&mut partial_witness, targets, out_targets)?;

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
    fn test_pairwise_hash() {
        let f_0 = F::ZERO;
        let f_1 = F::ONE;

        let f_0_hash = PoseidonHash::hash_or_noop(&[f_0]);
        let f_1_hash = PoseidonHash::hash_or_noop(&[f_1]);

        let pairwise_hash = PairwiseHash::new(vec![f_0], f_0_hash, vec![f_1], f_1_hash);
        assert!(pairwise_hash.prove_and_verify().is_ok());
    }

    #[test]
    fn test_pairwise_hash_well_formed() {
        let f_0 = F::ZERO;
        let f_1 = F::ONE;

        let f_0_hash = PoseidonHash::hash_or_noop(&[f_0]);
        let f_1_hash = PoseidonHash::hash_or_noop(&[f_1]);

        let pairwise_hash = PairwiseHash::new(vec![f_0], f_0_hash, vec![f_1], f_1_hash);
        assert_eq!(
            pairwise_hash.parent_hash,
            PoseidonHash::hash_or_noop(
                &[
                    PoseidonHash::hash_or_noop(&[f_0]).elements,
                    PoseidonHash::hash_or_noop(&[f_1]).elements
                ]
                .concat()
            )
        );
    }
}
