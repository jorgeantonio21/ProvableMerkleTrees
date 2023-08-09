use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

pub mod circuit_compiler;
pub mod merkle_tree;
pub mod pairwise_hash;
pub mod provable;

pub const D: usize = 2;
pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
