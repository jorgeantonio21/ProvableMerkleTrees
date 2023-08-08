use anyhow::Error;
use plonky2::{
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::witness::PartialWitness,
    iop::witness::WitnessWrite,
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{
    provable::{CircuitCompiler, ProofData, Provable},
    C, D, F,
};

pub(crate) struct RecursiveHash {
    pub(crate) left_hash: HashOut<F>,
    pub(crate) right_hash: HashOut<F>,
    pub(crate) parent_hash: HashOut<F>,
}

impl RecursiveHash {
    pub fn hash_inputs(left_hash: HashOut<F>, right_hash: HashOut<F>) -> Self {
        let parent_hash =
            PoseidonHash::hash_no_pad(&[left_hash.elements, right_hash.elements].concat());
        Self {
            left_hash,
            right_hash,
            parent_hash,
        }
    }
}

impl CircuitCompiler<F, D> for RecursiveHash {
    type Value = HashOut<F>;
    type Targets = [HashOutTarget; 2];
    type OutTargets = HashOutTarget;

    fn evaluate(&self) -> Self::Value {
        self.parent_hash
    }

    fn compile(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets) {
        let left_hash_targets = circuit_builder.add_virtual_hash();
        let right_hash_targets = circuit_builder.add_virtual_hash();
        let parent_hash_targets = circuit_builder.add_virtual_hash();

        let should_be_parent_hash_targets = circuit_builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            [left_hash_targets.elements, right_hash_targets.elements].concat(),
        );

        circuit_builder.connect_hashes(parent_hash_targets, should_be_parent_hash_targets);

        let hash_targets = [left_hash_targets, right_hash_targets];
        (hash_targets, parent_hash_targets)
    }

    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error> {
        let left_hash_targets = targets[0];
        let right_hash_targets = targets[1];
        let parent_hash_targets = out_targets;

        (0..4).for_each(|i| {
            partial_witness.set_target(left_hash_targets.elements[i], self.left_hash.elements[i]);
            partial_witness.set_target(right_hash_targets.elements[i], self.right_hash.elements[i]);
            partial_witness.set_target(
                parent_hash_targets.elements[i],
                self.parent_hash.elements[i],
            );
        });

        Ok(())
    }
}

impl Provable<F, C, D> for RecursiveHash {
    fn proof(
        &self,
        mut circuit_builder: CircuitBuilder<F, D>,
        mut partial_witness: PartialWitness<F>,
    ) -> Result<ProofData<F, C, D>, Error> {
        let (targets, out_targets) = self.compile(&mut circuit_builder);
        self.fill(&mut partial_witness, targets, out_targets)?;

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data.prove(partial_witness)?;

        Ok(ProofData {
            proof_with_pis,
            common: circuit_data.common,
            verifier_only: circuit_data.verifier_only,
        })
    }
}
