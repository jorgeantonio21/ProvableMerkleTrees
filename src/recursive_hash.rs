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
    pub(crate) hash: HashOut<F>,
    pub(crate) proof_data: ProofData<F, C, D>,
}

impl RecursiveHash {
    pub fn new(hash: HashOut<F>, proof_data: ProofData<F, C, D>) -> Self {
        Self { hash, proof_data }
    }
}

pub struct RecursivePairwiseHash {
    pub(crate) left_recursive_hash: RecursiveHash,
    pub(crate) right_recursive_hash: RecursiveHash,
    pub(crate) parent_hash: HashOut<F>,
}

impl RecursivePairwiseHash {
    pub fn new(left_recursive_hash: RecursiveHash, right_recursive_hash: RecursiveHash) -> Self {
        let parent_hash = PoseidonHash::hash_or_noop(
            &[
                left_recursive_hash.hash.elements,
                right_recursive_hash.hash.elements,
            ]
            .concat(),
        );
        Self {
            left_recursive_hash,
            right_recursive_hash,
            parent_hash,
        }
    }
}

impl CircuitCompiler<F, D> for RecursivePairwiseHash {
    type Value = HashOut<F>;
    type Targets = (
        HashOutTarget,
        HashOutTarget,
        ProofWithPublicInputsTarget<D>,
        VerifierCircuitTarget,
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
        let left_proof_with_pis_targets = circuit_builder
            .add_virtual_proof_with_pis(&self.left_recursive_hash.proof_data.circuit_data.common);
        let left_verifier_data_targets = circuit_builder.add_virtual_verifier_data(
            self.left_recursive_hash
                .proof_data
                .circuit_data
                .common
                .config
                .fri_config
                .cap_height,
        );

        let right_proof_with_pis_targets = circuit_builder
            .add_virtual_proof_with_pis(&self.right_recursive_hash.proof_data.circuit_data.common);
        let right_verifier_data_targets = circuit_builder.add_virtual_verifier_data(
            self.right_recursive_hash
                .proof_data
                .circuit_data
                .common
                .config
                .fri_config
                .cap_height,
        );

        // we need to enforce that the public inputs of `proof_with_pis_targets` do agree
        // with the child hash targets
        let true_bool_target = circuit_builder._true();
        let false_bool_target = circuit_builder._false();
        if left_proof_with_pis_targets.public_inputs.len() != 4 {
            circuit_builder.connect(true_bool_target.target, false_bool_target.target);
        }
        (0..4).for_each(|i| {
            circuit_builder.connect(
                left_proof_with_pis_targets.public_inputs[i],
                left_hash_targets.elements[i],
            )
        });

        if right_proof_with_pis_targets.public_inputs.len() != 4 {
            circuit_builder.connect(true_bool_target.target, false_bool_target.target);
        }
        (0..4).for_each(|i| {
            circuit_builder.connect(
                right_proof_with_pis_targets.public_inputs[i],
                right_hash_targets.elements[i],
            )
        });

        (
            (
                left_hash_targets,
                right_hash_targets,
                left_proof_with_pis_targets,
                left_verifier_data_targets,
                right_proof_with_pis_targets,
                right_verifier_data_targets,
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
        let (
            left_hash_targets,
            right_hash_targets,
            left_proof_with_pis_targets,
            left_verifier_data_targets,
            right_proof_with_pis_targets,
            right_verifier_data_targets,
        ) = targets;

        partial_witness.set_hash_target(left_hash_targets, self.left_recursive_hash.hash);
        partial_witness.set_hash_target(right_hash_targets, self.right_recursive_hash.hash);
        partial_witness.set_hash_target(out_targets, self.parent_hash);

        partial_witness.set_proof_with_pis_target(
            &left_proof_with_pis_targets,
            &self.left_recursive_hash.proof_data.proof_with_pis,
        );
        partial_witness.set_verifier_data_target(
            &left_verifier_data_targets,
            &self
                .left_recursive_hash
                .proof_data
                .circuit_data
                .verifier_only,
        );

        partial_witness.set_proof_with_pis_target(
            &right_proof_with_pis_targets,
            &self.right_recursive_hash.proof_data.proof_with_pis,
        );
        partial_witness.set_verifier_data_target(
            &right_verifier_data_targets,
            &self
                .right_recursive_hash
                .proof_data
                .circuit_data
                .verifier_only,
        );

        Ok(())
    }
}

impl Provable<F, C, D> for RecursivePairwiseHash {
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
    use plonky2::field::types::Field;

    use super::*;

    #[test]
    fn test_recursive_pairwise_hash() {
        let left_hash = PoseidonHash::hash_or_noop(&[F::ZERO]);
        let right_hash = PoseidonHash::hash_or_noop(&[F::ONE]);

        let mut circuit_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut partial_witness = PartialWitness::<F>::new();

        let left_hash_targets = circuit_builder.add_virtual_hash();
        circuit_builder.register_public_inputs(&left_hash_targets.elements);
        partial_witness.set_hash_target(left_hash_targets, left_hash);

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data
            .prove(partial_witness)
            .expect("Failed to prove left hash");

        let left_proof_data = ProofData {
            circuit_data,
            proof_with_pis,
        };

        let left_recursive_hash = RecursiveHash::new(left_hash, left_proof_data);

        let mut circuit_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut partial_witness = PartialWitness::<F>::new();

        let right_hash_targets = circuit_builder.add_virtual_hash();
        circuit_builder.register_public_inputs(&right_hash_targets.elements);
        partial_witness.set_hash_target(right_hash_targets, right_hash);

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data
            .prove(partial_witness)
            .expect("Failed to prove left hash");

        let right_proof_data = ProofData {
            circuit_data,
            proof_with_pis,
        };

        let right_recursive_hash = RecursiveHash::new(right_hash, right_proof_data);

        let recursive_pairwise_hash =
            RecursivePairwiseHash::new(left_recursive_hash, right_recursive_hash);

        assert!(recursive_pairwise_hash.prove_and_verify().is_ok());
    }

    #[test]
    #[should_panic]
    fn test_recursive_pairwise_hash_fails_if_hash_is_invalid() {
        let left_hash = PoseidonHash::hash_or_noop(&[F::ZERO]);
        let right_hash = PoseidonHash::hash_or_noop(&[F::ONE]);

        let mut circuit_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut partial_witness = PartialWitness::<F>::new();

        let left_hash_targets = circuit_builder.add_virtual_hash();
        circuit_builder.register_public_inputs(&left_hash_targets.elements);
        partial_witness.set_hash_target(left_hash_targets, left_hash);

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data
            .prove(partial_witness)
            .expect("Failed to prove left hash");

        let left_proof_data = ProofData {
            circuit_data,
            proof_with_pis,
        };

        let left_recursive_hash = RecursiveHash::new(left_hash, left_proof_data);

        let mut circuit_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut partial_witness = PartialWitness::<F>::new();

        let right_hash_targets = circuit_builder.add_virtual_hash();
        circuit_builder.register_public_inputs(&right_hash_targets.elements);
        partial_witness.set_hash_target(right_hash_targets, right_hash);

        let circuit_data = circuit_builder.build::<C>();
        let proof_with_pis = circuit_data
            .prove(partial_witness)
            .expect("Failed to prove left hash");

        let right_proof_data = ProofData {
            circuit_data,
            proof_with_pis,
        };

        let right_recursive_hash = RecursiveHash::new(right_hash, right_proof_data);

        let mut recursive_pairwise_hash =
            RecursivePairwiseHash::new(left_recursive_hash, right_recursive_hash);

        recursive_pairwise_hash.left_recursive_hash.hash =
            PoseidonHash::hash_or_noop(&[F::from_canonical_u8(255)]);
        assert!(recursive_pairwise_hash.prove_and_verify().is_err());
    }
}
