use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

pub mod merkle_tree;
pub mod provable;
pub mod recursive_hash;

pub const D: usize = 2;
pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
