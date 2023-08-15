use crate::circuit_compiler::ProofData;
use anyhow::Error;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};

/// `Provable` Trait
///     A trait defining the functionality for generating and verifying proofs for a circuit.
///
/// Type Parameters:
///
///     F: A type parameter representing the field type used for calculations.
///     C: A type parameter representing the circuit configuration.
///     D: A type parameter representing the dimension.
pub trait Provable<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
where
    Self: Sized,
{
    /// Method `proof`:
    ///     Generates a proof for the circuit.
    ///
    /// Returns:
    ///
    ///     Returns a Result containing the generated ProofData or an Error if the proof generation fails.
    fn proof(self) -> Result<ProofData<F, C, D>, Error>;
    /// Method `proof_and_verify`:
    ///     
    ///     Generates and verifies a proof for the circuit in one step.
    ///
    /// Returns:
    ///
    ///     Returns a Result indicating success or an Error if the proof generation or verification fails.
    fn prove_and_verify(self) -> Result<(), Error> {
        let proof_data = self.proof()?;
        proof_data.circuit_data.verify(proof_data.proof_with_pis)
    }
}
