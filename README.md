# ProvableMerkleTrees

## Introduction

This repo provides Rust code to build a `MerkleTree` structure together with a `Provable` interface to generate Zero Knowledge proofs
to attest that the structure of the Merkle Tree is well formed. That is, the provided root is generated via recursive hashes of parent and child nodes.

We use Plonky2 as our proof system, as we rely heavily on recursion to generate proofs. The way it works, is by recursively proof and verify that each two consecutive pair of `(left_child_hash, right_child_hash)` together with the corresponding `parent_hash` is well formed (i.e., that latter is the `Poseidon` hash of its child).

## Implementation considerations:

1. We use `PoseidonHash` as our native hash function. We use the `Goldilocks` field, as our natural choice of field.
2. We define a `Provable` interface, which `MerkleTree` implements to generate proof data right away (to later be verified).
This has the advantage to abstract away the creation and use of circuits and witnesses. Leaving the user, with simple to use methods
to generate/verify proofs.
3. We make auxiliary use of a `CircuitCompiler` interface, that allows to evaluate a type (think of the evaluation of a `MerkleTree` to be its root), compile its value to a circuit and to fill the circuit targets with the corresponding type values.
4. We use a structure `PairwiseHash` to encapsulate the logic of a parent hash generated from a pair of left and right child hashes.
5. The `PairwiseHash` struct also implements the `Provable` (and `CircuitCompiler`) interface, which then is used to recursively
verify the `MerkleTree` hashing generation.
6. We provide extensive testing, that verify that a given well generated Merkle Tree is proved and verified correctly, as well, as this
fails for ill formed Merkle Trees (by changing data, root and digests).
