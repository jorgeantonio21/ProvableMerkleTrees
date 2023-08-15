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

/// `RecursiveHash`
///
///     A structure representing a hash operation within a recursive context.
///
/// Fields:
///
///     hash: A HashOut<F> representing the hash value.
///     proof_data: A reference to ProofData<F, C, D> containing proof-related data.
pub struct RecursiveHash<'a> {
    pub(crate) hash: HashOut<F>,
    pub(crate) proof_data: &'a ProofData<F, C, D>,
}

impl<'a> RecursiveHash<'a> {
    /// Method `new`:
    ///
    ///     Creates a new instance of RecursiveHash.
    ///
    /// Arguments:
    ///
    ///     hash: A HashOut<F> representing the hash value.
    ///     proof_data: A reference to ProofData<F, C, D> containing proof-related data.
    ///
    /// Returns:
    ///
    ///     Returns a RecursiveHash instance with the provided hash and proof data.
    pub fn new(hash: HashOut<F>, proof_data: &'a ProofData<F, C, D>) -> Self {
        Self { hash, proof_data }
    }
}

/// `RecursivePairwiseHash`
///
///     A structure representing a recursive pairwise hash operation between two child RecursiveHash instances and their parent hash.
///
/// Fields:
///
///     left_recursive_hash: A RecursiveHash instance representing the left child.
///     right_recursive_hash: A RecursiveHash instance representing the right child.
///     parent_hash: A HashOut<F> representing the hash value of the parent.
pub struct RecursivePairwiseHash<'a> {
    pub(crate) left_recursive_hash: RecursiveHash<'a>,
    pub(crate) right_recursive_hash: RecursiveHash<'a>,
    pub(crate) parent_hash: HashOut<F>,
}

impl<'a> RecursivePairwiseHash<'a> {
    /// Method `new`:
    ///
    ///     Creates a new instance of RecursivePairwiseHash.
    ///
    /// Arguments:
    ///
    ///     left_recursive_hash: A RecursiveHash instance representing the left child.
    ///     right_recursive_hash: A RecursiveHash instance representing the right child.
    ///
    /// Returns:
    ///
    ///     Returns a RecursivePairwiseHash instance with the provided child hash instances.
    pub fn new(
        left_recursive_hash: RecursiveHash<'a>,
        right_recursive_hash: RecursiveHash<'a>,
    ) -> Self {
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

impl<'a> CircuitCompiler<F, D> for RecursivePairwiseHash<'a> {
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

    /// `CircuitCompiler` trait method `evaluate`:
    ///
    ///     Evaluates the recursive pairwise hash operation and returns the resulting HashOut<F>.
    fn evaluate(&self) -> Self::Value {
        self.parent_hash
    }

    /// `CircuitCompiler` trait method `compile`:
    ///
    ///     Compiles the circuit for the recursive pairwise hash operation.
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

impl<'a> Provable<F, C, D> for RecursivePairwiseHash<'a> {
    /// `Provable` trait method `proof`:
    ///
    ///     Generates a proof for the recursive pairwise hash operation.
    ///
    /// Returns:
    ///
    ///     Returns a Result containing the generated ProofData or an Error if the proof generation fails.
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

        let left_recursive_hash = RecursiveHash::new(left_hash, &left_proof_data);

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

        let right_recursive_hash = RecursiveHash::new(right_hash, &right_proof_data);

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

        let left_recursive_hash = RecursiveHash::new(left_hash, &left_proof_data);

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

        let right_recursive_hash = RecursiveHash::new(right_hash, &right_proof_data);

        let mut recursive_pairwise_hash =
            RecursivePairwiseHash::new(left_recursive_hash, right_recursive_hash);

        recursive_pairwise_hash.left_recursive_hash.hash =
            PoseidonHash::hash_or_noop(&[F::from_canonical_u8(255)]);
        assert!(recursive_pairwise_hash.prove_and_verify().is_err());
    }
}
