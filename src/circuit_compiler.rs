use anyhow::Error;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitData, config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
};

/// `ProofData`:
///
///     A structure representing proof-related data for a specific circuit.
///
/// Type Parameters:
///
///     F: A type parameter representing the field type used for calculations.
///     C: A type parameter representing the circuit configuration.
///     D: A type parameter representing the dimension.
///
/// Fields:
///
///     proof_with_pis: A ProofWithPublicInputs<F, C, D> instance representing the proof with public inputs.
///     circuit_data: A CircuitData<F, C, D> instance representing the circuit data.
pub struct ProofData<F, C: GenericConfig<D, F = F>, const D: usize>
where
    F: RichField + Extendable<D>,
{
    pub(crate) proof_with_pis: ProofWithPublicInputs<F, C, D>,
    pub(crate) circuit_data: CircuitData<F, C, D>,
}

/// `CircuitCompiler` Trait:
///
///     A trait representing the functionality for compiling and processing a circuit.
///
/// Type Parameters:
///
///     F: A type parameter representing the field type used for calculations.
///     D: A type parameter representing the dimension.
///
/// Associated Types:
///
///     Value: The type that represents the result of evaluating the circuit.
///     Targets: A tuple type representing the targets used during circuit compilation.
///     OutTargets: A type representing the output targets used during circuit compilation.
pub trait CircuitCompiler<F: RichField + Extendable<D>, const D: usize> {
    type Value;
    type Targets;
    type OutTargets;

    /// Method `evaluate`:
    ///     
    ///     Evaluates the circuit and returns the resulting value of type Value.
    ///
    /// Returns:
    ///
    ///     Returns a value of type Value representing the result of evaluating the circuit.
    fn evaluate(&self) -> Self::Value;
    /// Method `compile`:
    ///     Compiles the circuit using the provided CircuitBuilder.
    ///
    /// Arguments:
    ///
    ///     circuit_builder: A mutable reference to a CircuitBuilder<F, D> instance used for circuit compilation.
    ///
    /// Returns:
    ///
    /// Returns a tuple containing Targets representing targets used during compilation and OutTargets representing output targets.
    fn compile(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets);
    /// Method `fill`:
    ///
    ///     Fills the PartialWitness with data for the compiled circuit.
    ///
    /// Arguments:
    ///
    ///     partial_witness: A mutable reference to a PartialWitness<F> instance to be filled.
    ///     targets: Targets representing the targets used during compilation.
    ///     out_targets: OutTargets representing output targets used during compilation.
    ///
    /// Returns:
    ///
    ///     Returns a Result indicating success or an Error in case of a failure.
    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), Error>;
}
