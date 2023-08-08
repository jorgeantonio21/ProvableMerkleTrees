use anyhow::Error;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
};

pub struct ProofData<F, C: GenericConfig<D, F = F>, const D: usize>
where
    F: RichField + Extendable<D>,
{
    pub(crate) proof_with_pis: ProofWithPublicInputs<F, C, D>,
    pub(crate) common: CommonCircuitData<F, D>,
    pub(crate) verifier_only: VerifierOnlyCircuitData<C, D>,
}

pub trait CircuitCompiler<F: RichField + Extendable<D>, const D: usize> {
    type Value;
    type Targets;
    type OutTargets;

    fn evaluate(&self) -> Self::Value;
    fn compile(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets);
    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), Error>;
}

pub trait Provable<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>:
    CircuitCompiler<F, D>
{
    fn proof(
        &self,
        circuit_builder: CircuitBuilder<F, D>,
        partial_witness: PartialWitness<F>,
    ) -> Result<ProofData<F, C, D>, Error>;
}
