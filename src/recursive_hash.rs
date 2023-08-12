use plonky2::{
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitTarget},
        config::Hasher,
        proof::ProofWithPublicInputsTarget,
    },
};

use crate::{
    circuit_compiler::{CircuitCompiler, ProofData},
    provable::Provable,
    C, D, F,
};

pub struct RecursiveHash {
    pub(crate) left_hash: HashOut<F>,
    pub(crate) right_hash: HashOut<F>,
    pub(crate) parent_hash: HashOut<F>,
    pub(crate) proof_data: ProofData<F, C, D>,
}

impl RecursiveHash {
    pub fn new(
        left_hash: HashOut<F>,
        right_hash: HashOut<F>,
        proof_data: ProofData<F, C, D>,
    ) -> Self {
        let parent_hash =
            PoseidonHash::hash_or_noop(&[left_hash.elements, right_hash.elements].concat());
        Self {
            left_hash,
            right_hash,
            parent_hash,
            proof_data,
        }
    }
}

impl CircuitCompiler<F, D> for RecursiveHash {
    type Value = HashOut<F>;
    type Targets = (
        HashOutTarget,
        HashOutTarget,
        ProofWithPublicInputsTarget<D>,
        VerifierCircuitTarget,
    );
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
        circuit_builder.register_public_inputs(&parent_hash_targets.elements);

        let should_be_parent_hash_targets = circuit_builder.hash_or_noop::<PoseidonHash>(
            [left_hash_targets.elements, right_hash_targets.elements].concat(),
        );

        circuit_builder.connect_hashes(should_be_parent_hash_targets, parent_hash_targets);

        // add targets for recursion
        let proof_with_pis_targets =
            circuit_builder.add_virtual_proof_with_pis(&self.proof_data.circuit_data.common);
        let verifier_data_targets = circuit_builder.add_virtual_verifier_data(
            self.proof_data
                .circuit_data
                .common
                .config
                .fri_config
                .cap_height,
        );

        (
            (
                left_hash_targets,
                right_hash_targets,
                proof_with_pis_targets,
                verifier_data_targets,
            ),
            parent_hash_targets,
        )
    }

    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error> {
        let (left_hash_targets, right_hash_targets, proof_with_pis_targets, verifier_data_targets) =
            targets;

        partial_witness.set_hash_target(left_hash_targets, self.left_hash);
        partial_witness.set_hash_target(right_hash_targets, self.right_hash);
        partial_witness.set_hash_target(out_targets, self.parent_hash);
        partial_witness
            .set_proof_with_pis_target(&proof_with_pis_targets, &self.proof_data.proof_with_pis);
        partial_witness.set_verifier_data_target(
            &verifier_data_targets,
            &self.proof_data.circuit_data.verifier_only,
        );

        Ok(())
    }
}

impl Provable<F, C, D> for RecursiveHash {
    fn proof(self) -> Result<ProofData<F, C, D>, anyhow::Error> {
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
    use super::*;
}
