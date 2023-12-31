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
    circuit_compiler::{CircuitCompiler, EvaluateFillCircuit, ProofData},
    provable::Provable,
    C, D, F,
};

#[derive(Clone, Debug)]
pub struct HashData {
    pub(crate) data: Vec<F>,
    pub(crate) hash: HashOut<F>,
}

impl HashData {
    pub(crate) fn new(data: Vec<F>, hash: HashOut<F>) -> Self {
        Self { data, hash }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PairwiseHash {
    pub(crate) left_child: HashData,
    pub(crate) right_child: HashData,
    pub(crate) parent_hash: HashOut<F>,
}

impl PairwiseHash {
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

impl CircuitCompiler<C, F, D> for PairwiseHash {
    type Targets = (Vec<Target>, Vec<Target>, HashOutTarget, HashOutTarget);
    type OutTargets = HashOutTarget;

    fn compile(&self) -> (CircuitBuilder<F, D>, Self::Targets, Self::OutTargets) {
        let mut circuit_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
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
            circuit_builder,
            (
                left_data_targets,
                right_data_targets,
                left_hash_targets,
                right_hash_targets,
            ),
            parent_hash_targets,
        )
    }
}

impl EvaluateFillCircuit<C, F, D> for PairwiseHash {
    type Value = HashOut<F>;

    fn evaluate(&self) -> Self::Value {
        self.parent_hash
    }

    fn fill(
        &self,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<PartialWitness<F>, anyhow::Error> {
        let mut partial_witness = PartialWitness::<F>::new();

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

        Ok(partial_witness)
    }
}

impl Provable<F, C, D> for PairwiseHash {
    fn proof(self) -> Result<ProofData<F, C, D>, Error> {
        let (circuit_data, targets, out_targets) = self.compile_and_build();
        let partial_witness = self.fill(targets, out_targets)?;

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
