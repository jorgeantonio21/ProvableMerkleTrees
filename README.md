# ProvableMerkleTrees

This repo provides Rust code to build a `MerkleTree` structure together with a `Provable` interface to generate Zero Knowledge proofs
that the structure of the Merkle Tree is well formed, that is, the provided root is generated via recursive hashes of parent and child nodes.