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

pub struct ProofData<F, C: GenericConfig<D, F = F>, const D: usize>
where
    F: RichField + Extendable<D>,
{
    pub(crate) proof_with_pis: ProofWithPublicInputs<F, C, D>,
    pub(crate) circuit_data: CircuitData<F, C, D>,
}

pub trait CircuitCompiler<C, F, const D: usize>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    type Targets;
    type OutTargets;

    fn compile(&self) -> (CircuitBuilder<F, D>, Self::Targets, Self::OutTargets);
    fn compile_and_build(&self) -> (CircuitData<F, C, D>, Self::Targets, Self::OutTargets) {
        let (circuit_builder, targets, out_targets) = self.compile();
        let circuit_data = circuit_builder.build::<C>();
        (circuit_data, targets, out_targets)
    }
}

pub trait EvaluateFillCircuit<C, F, const D: usize>: CircuitCompiler<C, F, D>
where
    C: GenericConfig<D, F = F>,
    F: RichField + Extendable<D>,
{
    type Value;

    fn evaluate(&self) -> Self::Value;
    fn fill(
        &self,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<PartialWitness<F>, Error>;
}
